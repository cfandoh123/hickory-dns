//! Policy, retry, and cache tests. TLS verification itself is covered by the
//! separate real-socket authenticated_dot tests; this provider models decisions.
use super::{ConnectionCacheKey, RecursorDnsHandle};
use crate::{
    ConnectionProvider, PoolContext, TlsConfig,
    config::{
        ConnectionConfig, NameServerConfig, OpportunisticEncryption, OpportunisticEncryptionConfig,
        ProtocolConfig, ResolverOpts, ServerOrderingStrategy,
    },
    connection_provider::TlsConfigIdentity,
    name_server::NameServer,
    name_server_pool::NameServerPool,
    net::{
        DnsError, NetError, NoRecords,
        runtime::TokioRuntimeProvider,
        xfer::{DnsHandle, FirstAnswer, Protocol},
    },
    proto::{
        op::{DnsRequest, DnsRequestOptions, DnsResponse, Message, Query, ResponseCode},
        rr::{
            Name, RData, Record, RecordType,
            rdata::{CNAME, NS},
        },
    },
    recursor::{
        DnssecPolicy, ForcedEncryptedAuthoritativeConfig, ForcedEncryptedAuthoritativePolicy,
        ForcedEncryptedAuthoritativePolicyError, Recursor, RecursorError, RecursorMode,
        RecursorOptions,
    },
};
use futures_util::stream;
use rustls::pki_types::{CertificateDer, pem::PemObject};
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr},
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const CA: &str = include_str!("../../../../tests/test-data/authenticated-dot/ca.pem");
const ROGUE: &str = include_str!("../../../../tests/test-data/authenticated-dot/rogue-ca.pem");
const ROOT: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
const PRIMARY: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53));
const SECONDARY: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 57));
const PLAIN: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 58));
const PRIMARY_NAME: &str = "ns.primary.test";
const SECONDARY_NAME: &str = "ns.secondary.test";
type Reply = dyn Fn(IpAddr, Message) -> Message + Send + Sync;

#[derive(Clone, Copy)]
enum Failure {
    Refused,
    Certificate,
    Stall,
}

struct Call {
    ip: IpAddr,
    config: ConnectionConfig,
    identity: Option<TlsConfigIdentity>,
}
struct State {
    calls: Mutex<Vec<Call>>,
    queries: Mutex<Vec<(IpAddr, Query)>>,
    failures: Mutex<HashMap<IpAddr, Failure>>,
    reply: Arc<Reply>,
}

#[derive(Clone)]
struct Provider {
    runtime: TokioRuntimeProvider,
    state: Arc<State>,
}
impl Provider {
    fn new(reply: impl Fn(IpAddr, Message) -> Message + Send + Sync + 'static) -> Self {
        Self {
            runtime: TokioRuntimeProvider::new(),
            state: Arc::new(State {
                calls: Mutex::new(vec![]),
                queries: Mutex::new(vec![]),
                failures: Mutex::new(HashMap::new()),
                reply: Arc::new(reply),
            }),
        }
    }
    fn fail(&self, ip: IpAddr, failure: Failure) {
        self.state.failures.lock().unwrap().insert(ip, failure);
    }
    fn called(&self, ip: IpAddr) -> bool {
        self.state
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|call| call.ip == ip)
    }
    fn assert_tls_only(&self) {
        let calls = self.state.calls.lock().unwrap();
        assert!(!calls.is_empty());
        for call in calls.iter() {
            assert!(matches!(call.config.protocol, ProtocolConfig::Tls { .. }));
            assert_eq!(call.config.port, 853);
            assert!(call.identity.is_some());
        }
    }
}

impl ConnectionProvider for Provider {
    type Conn = Connection;
    type FutureConn = Pin<Box<dyn Future<Output = Result<Connection, NetError>> + Send>>;
    type RuntimeProvider = TokioRuntimeProvider;
    fn runtime_provider(&self) -> &Self::RuntimeProvider {
        &self.runtime
    }
    fn new_connection(
        &self,
        ip: IpAddr,
        config: &ConnectionConfig,
        cx: &PoolContext,
    ) -> Result<Self::FutureConn, NetError> {
        self.state.calls.lock().unwrap().push(Call {
            ip,
            config: config.clone(),
            identity: cx
                .server_tls_configs
                .get(&ip)
                .map(|server| server.identity.clone()),
        });
        let failure = self.state.failures.lock().unwrap().get(&ip).copied();
        let state = self.state.clone();
        Ok(Box::pin(async move {
            let source = match failure {
                Some(Failure::Stall) => return std::future::pending().await,
                Some(Failure::Refused) => Some(NetError::from(io::Error::from(
                    io::ErrorKind::ConnectionRefused,
                ))),
                Some(Failure::Certificate) => Some(NetError::from(
                    rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer),
                )),
                None => None,
            };
            if let Some(source) = source {
                return Err(NetError::RequiredTransportFailure {
                    server: ip,
                    source: Arc::new(source),
                });
            }
            Ok(Connection { ip, state })
        }))
    }
}

#[derive(Clone)]
struct Connection {
    ip: IpAddr,
    state: Arc<State>,
}
impl DnsHandle for Connection {
    type Runtime = TokioRuntimeProvider;
    type Response = stream::Iter<std::vec::IntoIter<Result<DnsResponse, NetError>>>;
    fn send(&self, request: DnsRequest) -> Self::Response {
        let query = request.queries[0].clone();
        self.state
            .queries
            .lock()
            .unwrap()
            .push((self.ip, query.clone()));
        let response = (self.state.reply)(self.ip, request.into_parts().0);
        let result = if response.response_code == ResponseCode::NXDomain
            || (response.answers.is_empty()
                && response.authoritative
                && response.authorities.is_empty())
        {
            Err(
                DnsError::NoRecordsFound(NoRecords::new(Box::new(query), response.response_code))
                    .into(),
            )
        } else {
            DnsResponse::from_message(response).map_err(NetError::from)
        };
        stream::iter(vec![result])
    }
}

fn name(value: &str) -> Name {
    Name::from_ascii(value).unwrap()
}
fn query(value: &str) -> Query {
    Query::new(name(value), RecordType::A)
}
fn response(ip: IpAddr, request: Message) -> Message {
    let query = request.queries[0].clone();
    let mut response = request.into_response();
    response.authoritative = true;
    if query.name.to_ascii().starts_with("missing.") {
        response.response_code = ResponseCode::NXDomain;
    } else if query.query_type == RecordType::A && !query.name.to_ascii().starts_with("nodata.") {
        let address = if ip == PLAIN {
            Ipv4Addr::new(198, 51, 100, 66)
        } else {
            Ipv4Addr::new(192, 0, 2, 20)
        };
        response.add_answer(Record::from_rdata(query.name, 30, RData::from(address)));
    }
    response
}
fn policy(bindings: serde_json::Value) -> serde_json::Value {
    serde_json::json!({"servers":[
        {"name":PRIMARY_NAME,"address":PRIMARY.to_string(),"protocol":"dot","trust_anchor":CA},
        {"name":SECONDARY_NAME,"address":SECONDARY.to_string(),"protocol":"dot","trust_anchor":CA}
    ], "zones":bindings})
}
fn resolver(
    provider: &Provider,
    bindings: serde_json::Value,
    opportunistic: bool,
) -> Recursor<Provider> {
    let config: ForcedEncryptedAuthoritativeConfig =
        serde_json::from_value(policy(bindings)).unwrap();
    let policy = ForcedEncryptedAuthoritativePolicy::try_from(config).unwrap();
    let mut options = RecursorOptions {
        deny_server: vec![],
        ..Default::default()
    };
    if opportunistic {
        options.opportunistic_encryption = OpportunisticEncryption::Enabled {
            config: OpportunisticEncryptionConfig {
                max_concurrent_probes: 0,
                ..Default::default()
            },
        };
    }
    Recursor::new_with_policy(
        &[ROOT],
        DnssecPolicy::SecurityUnaware,
        None,
        options,
        provider.clone(),
        Some(Arc::new(policy)),
    )
    .unwrap()
}
fn binding(servers: &[&str]) -> serde_json::Value {
    serde_json::json!([{"name":"bound.test.","servers":servers}])
}
fn handle(recursor: &Recursor<Provider>) -> &RecursorDnsHandle<Provider> {
    match &recursor.mode {
        RecursorMode::NonValidating { handle } => handle,
        _ => panic!("unexpected validation mode"),
    }
}
async fn lookup(recursor: &Recursor<Provider>, value: &str) -> Result<Message, RecursorError> {
    tokio::time::timeout(
        Duration::from_secs(2),
        recursor.resolve(query(value), Instant::now(), false),
    )
    .await
    .unwrap()
}
fn good(message: &Message) {
    assert_eq!(message.response_code, ResponseCode::NoError);
    assert!(
        message
            .answers
            .iter()
            .any(|record| record.data.ip_addr() == Some("192.0.2.20".parse().unwrap()))
    );
    assert!(
        !message
            .answers
            .iter()
            .any(|record| record.data.ip_addr() == Some("198.51.100.66".parse().unwrap()))
    );
}

#[test]
fn zone_bindings_are_validated_normalized_and_use_longest_match() {
    let config: ForcedEncryptedAuthoritativeConfig =
        serde_json::from_value(policy(serde_json::json!([
            {"name":"BOUND.TEST","servers":["NS.PRIMARY.TEST."]},
            {"name":"child.bound.test.","servers":[SECONDARY_NAME]}
        ])))
        .unwrap();
    let policy = ForcedEncryptedAuthoritativePolicy::try_from(config).unwrap();
    assert_eq!(
        policy.zone_for(&name("host.BOUND.test.")).unwrap().1,
        &[PRIMARY]
    );
    assert_eq!(
        policy.zone_for(&name("host.child.bound.test.")).unwrap().1,
        &[SECONDARY]
    );
    assert!(policy.zone_for(&name("notbound.test.")).is_none());
    for zones in [
        serde_json::json!([{"name":"bound.test.","servers":[]}]),
        serde_json::json!([{"name":"*.bound.test.","servers":[PRIMARY_NAME]}]),
        serde_json::json!([{"name":"bound.test.","servers":[PRIMARY_NAME]}, {"name":"BOUND.TEST","servers":[SECONDARY_NAME]}]),
    ] {
        let config: ForcedEncryptedAuthoritativeConfig =
            serde_json::from_value(policy_value(zones)).unwrap();
        assert!(matches!(
            ForcedEncryptedAuthoritativePolicy::try_from(config),
            Err(ForcedEncryptedAuthoritativePolicyError::InvalidZone { .. })
        ));
    }
    let config: ForcedEncryptedAuthoritativeConfig = serde_json::from_value(policy_value(
        serde_json::json!([{"name":"bound.test.","servers":["unknown.test."]}]),
    ))
    .unwrap();
    assert!(matches!(
        ForcedEncryptedAuthoritativePolicy::try_from(config),
        Err(ForcedEncryptedAuthoritativePolicyError::UnknownZoneServer { .. })
    ));
}

// Avoid shadowing the policy builder with the validated local variable above.
fn policy_value(zones: serde_json::Value) -> serde_json::Value {
    policy(zones)
}

#[tokio::test]
async fn protected_lookup_ignores_parent_and_unprotected_caches() {
    let provider = Provider::new(response);
    provider.fail(ROOT, Failure::Stall);
    let recursor = resolver(&provider, binding(&[PRIMARY_NAME]), false);
    let handle = handle(&recursor);
    let mut request = Message::query();
    request.add_query(query("host.bound.test."));
    handle.response_cache.insert(
        query("host.bound.test."),
        Ok(response(PLAIN, request)),
        Instant::now(),
    );
    handle.name_server_cache.lock().insert(
        name("bound.test."),
        NameServerPool::from_config(
            [NameServerConfig::udp_and_tcp(PLAIN)],
            handle.pool_context.clone(),
            provider.clone(),
        )
        .with_zone(name("bound.test.")),
    );
    good(&lookup(&recursor, "host.bound.test.").await.unwrap());
    let count = provider.state.calls.lock().unwrap().len();
    good(&lookup(&recursor, "host.bound.test.").await.unwrap());
    assert_eq!(provider.state.calls.lock().unwrap().len(), count);
    assert!(provider.called(PRIMARY));
    assert!(!provider.called(ROOT));
    assert!(!provider.called(PLAIN));
    provider.assert_tls_only();
}

#[tokio::test]
async fn failed_approved_server_retries_another_approved_server() {
    for opportunistic in [false, true] {
        let provider = Provider::new(response);
        provider.fail(PRIMARY, Failure::Certificate);
        let recursor = resolver(
            &provider,
            binding(&[PRIMARY_NAME, SECONDARY_NAME]),
            opportunistic,
        );
        let handle = handle(&recursor);
        handle
            .cached_name_server(&handle.name_server_config(SECONDARY))
            .record_cancelled(Duration::from_millis(50));
        good(&lookup(&recursor, "host.bound.test.").await.unwrap());
        assert!(provider.called(PRIMARY));
        assert!(provider.called(SECONDARY));
        assert!(!provider.called(ROOT));
        assert!(!provider.called(PLAIN));
        provider.assert_tls_only();
    }
}

#[tokio::test]
async fn all_approved_servers_failing_does_not_try_a_parent() {
    let provider = Provider::new(response);
    provider.fail(PRIMARY, Failure::Certificate);
    provider.fail(SECONDARY, Failure::Refused);
    let recursor = resolver(&provider, binding(&[PRIMARY_NAME, SECONDARY_NAME]), false);
    let error = lookup(&recursor, "host.bound.test.").await.unwrap_err();
    assert!(error.is_security_failure(), "{error:?}");
    assert!(provider.called(PRIMARY));
    assert!(provider.called(SECONDARY));
    assert!(!provider.called(ROOT));
    provider.assert_tls_only();
}

#[tokio::test]
async fn strict_pool_filters_plaintext_siblings_before_selection() {
    let provider = Provider::new(response);
    provider.fail(PRIMARY, Failure::Refused);
    let recursor = resolver(&provider, binding(&[PRIMARY_NAME]), false);
    let handle = handle(&recursor);
    let pool = NameServerPool::from_nameservers(
        vec![
            handle.cached_name_server(&NameServerConfig::udp_and_tcp(PLAIN)),
            handle.cached_name_server(&handle.name_server_config(PRIMARY)),
        ],
        handle.pool_context.clone(),
    )
    .with_required_authentication();
    assert!(
        pool.lookup(query("host.bound.test."), DnsRequestOptions::default())
            .first_answer()
            .await
            .is_err()
    );
    assert!(!provider.called(PLAIN));
    assert!(provider.called(PRIMARY));
    provider.assert_tls_only();
}

fn alias_reply(
    target: &'static str,
    include_inline: bool,
) -> impl Fn(IpAddr, Message) -> Message + Send + Sync {
    move |ip, request| {
        if request.queries[0].name.to_ascii().starts_with("alias.")
            && request.queries[0].query_type == RecordType::A
        {
            let source = request.queries[0].name.clone();
            let mut reply = request.into_response();
            reply.authoritative = true;
            reply.add_answer(Record::from_rdata(
                source,
                30,
                RData::CNAME(CNAME(name(target))),
            ));
            if include_inline {
                reply.add_answer(Record::from_rdata(
                    name(target),
                    30,
                    RData::from(Ipv4Addr::new(198, 51, 100, 66)),
                ));
            }
            reply
        } else {
            response(ip, request)
        }
    }
}

#[tokio::test]
async fn protected_cname_cannot_escape_to_an_unbound_zone() {
    let provider = Provider::new(alias_reply("target.outside.test.", true));
    let recursor = resolver(&provider, binding(&[PRIMARY_NAME]), false);
    let error = lookup(&recursor, "alias.bound.test.").await.unwrap_err();
    assert!(error.is_security_failure());
    assert!(!provider.called(ROOT));
    provider.assert_tls_only();
}

#[tokio::test]
async fn protected_cname_revalidates_inline_data_using_the_target_binding() {
    let provider = Provider::new(alias_reply("target.child.bound.test.", true));
    let recursor = resolver(
        &provider,
        serde_json::json!([
            {"name":"bound.test.","servers":[PRIMARY_NAME]},
            {"name":"child.bound.test.","servers":[SECONDARY_NAME]}
        ]),
        false,
    );
    good(&lookup(&recursor, "alias.bound.test.").await.unwrap());
    assert!(provider.called(PRIMARY));
    assert!(provider.called(SECONDARY));
    assert!(!provider.called(ROOT));
    provider.assert_tls_only();
}

#[tokio::test]
async fn any_and_cname_queries_do_not_accept_inline_records_owned_by_another_binding() {
    for query_type in [RecordType::ANY, RecordType::CNAME] {
        let provider = Provider::new(|_, request| {
            let source = request.queries[0].name.clone();
            let mut reply = request.into_response();
            reply.authoritative = true;
            reply.add_answer(Record::from_rdata(
                source,
                30,
                RData::CNAME(CNAME(name("target.child.bound.test."))),
            ));
            reply.add_answer(Record::from_rdata(
                name("target.child.bound.test."),
                30,
                RData::from(Ipv4Addr::new(198, 51, 100, 66)),
            ));
            reply
        });
        let recursor = resolver(
            &provider,
            serde_json::json!([
                {"name":"bound.test.","servers":[PRIMARY_NAME]},
                {"name":"child.bound.test.","servers":[SECONDARY_NAME]}
            ]),
            false,
        );
        let answer = recursor
            .resolve(
                Query::new(name("alias.bound.test."), query_type),
                Instant::now(),
                false,
            )
            .await
            .unwrap();
        assert_eq!(answer.answers.len(), 1);
        assert_eq!(answer.answers[0].record_type(), RecordType::CNAME);
        assert!(!provider.called(SECONDARY)); // These query types do not chase CNAMEs.
    }
}

#[tokio::test]
async fn ordinary_cname_cannot_supply_inline_data_for_a_protected_target() {
    let provider = Provider::new(alias_reply("target.bound.test.", true));
    let recursor = resolver(&provider, binding(&[PRIMARY_NAME]), false);
    good(&lookup(&recursor, "alias.ordinary.test.").await.unwrap());
    assert!(provider.called(ROOT));
    assert!(provider.called(PRIMARY));
}

#[tokio::test]
async fn protected_child_referral_without_a_binding_is_rejected() {
    let provider = Provider::new(|_, request| {
        let mut reply = request.into_response();
        reply.authoritative = false;
        reply.add_authority(Record::from_rdata(
            name("child.bound.test."),
            30,
            RData::NS(NS(name("ns.attacker.test."))),
        ));
        reply
    });
    let recursor = resolver(&provider, binding(&[PRIMARY_NAME]), false);
    assert!(
        lookup(&recursor, "host.child.bound.test.")
            .await
            .unwrap_err()
            .is_security_failure()
    );
    assert!(!provider.called(PLAIN));
    assert!(!provider.called(ROOT));
    provider.assert_tls_only();
}

#[tokio::test]
async fn authenticated_negative_answers_keep_their_dns_meaning() {
    let provider = Provider::new(response);
    let recursor = resolver(&provider, binding(&[PRIMARY_NAME]), false);
    let nx = lookup(&recursor, "missing.bound.test.").await.unwrap_err();
    assert!(nx.is_nx_domain());
    assert!(!nx.is_security_failure());
    let no_data = lookup(&recursor, "nodata.bound.test.").await.unwrap_err();
    assert!(no_data.is_no_records_found());
    assert!(!no_data.is_security_failure());
    provider.assert_tls_only();
}

#[tokio::test]
async fn ds_dependency_requires_an_authenticated_parent_binding() {
    let provider = Provider::new(response);
    let recursor = resolver(&provider, binding(&[PRIMARY_NAME]), false);
    let error = recursor
        .resolve(
            Query::new(name("bound.test."), RecordType::DS),
            Instant::now(),
            false,
        )
        .await
        .unwrap_err();
    assert!(error.is_security_failure());
    assert!(provider.state.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn connection_cache_distinguishes_protocol_port_name_and_trust_policy() {
    let provider = Provider::new(response);
    let recursor = resolver(&provider, binding(&[PRIMARY_NAME]), false);
    let handle = handle(&recursor);
    let config = handle.name_server_config(PRIMARY);
    let original = handle.cached_name_server(&config);
    assert!(Arc::ptr_eq(&original, &handle.cached_name_server(&config)));
    let mut other = config.clone();
    other.connections[0].port = 8853;
    assert!(!Arc::ptr_eq(&original, &handle.cached_name_server(&other)));
    other = config.clone();
    other.connections[0].protocol = ProtocolConfig::Tls {
        server_name: Arc::from("other.test"),
    };
    assert!(!Arc::ptr_eq(&original, &handle.cached_name_server(&other)));
    assert!(!Arc::ptr_eq(
        &original,
        &handle.cached_name_server(&NameServerConfig::tcp(PRIMARY))
    ));
    let original_key = ConnectionCacheKey {
        config: config.clone(),
        tls_identity: Some(
            handle.pool_context.server_tls_configs[&PRIMARY]
                .identity
                .clone(),
        ),
    };
    let other_key = ConnectionCacheKey {
        config,
        tls_identity: Some(TlsConfigIdentity::new(client_tls(ROGUE))),
    };
    assert_eq!(HashSet::from([original_key, other_key]).len(), 2);
}

fn client_tls(ca: &str) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(ca.as_bytes()) {
        roots.add(certificate.unwrap()).unwrap();
    }
    rustls::ClientConfig::builder_with_provider(Arc::new(crate::net::tls::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

#[tokio::test]
async fn native_provider_rejects_wrong_protocol_port_and_name_before_connecting() {
    let provider = TokioRuntimeProvider::new();
    let cx = PoolContext::new(ResolverOpts::default(), TlsConfig::new().unwrap())
        .with_server_tls_config(PRIMARY, Arc::from(PRIMARY_NAME), client_tls(CA));
    let mut wrong_port =
        NameServerConfig::tls(PRIMARY, Arc::from(PRIMARY_NAME)).connections[0].clone();
    wrong_port.port = 8853;
    for config in [
        NameServerConfig::udp_and_tcp(PRIMARY).connections[0].clone(),
        NameServerConfig::tcp(PRIMARY).connections[0].clone(),
        NameServerConfig::tls(PRIMARY, Arc::from("wrong.test")).connections[0].clone(),
        wrong_port,
    ] {
        assert!(matches!(
            provider.new_connection(PRIMARY, &config, &cx),
            Err(NetError::SecurityPolicy(_))
        ));
    }
}

#[tokio::test]
async fn authenticated_servfail_and_refused_retry_an_approved_backup() {
    for code in [ResponseCode::ServFail, ResponseCode::Refused] {
        let provider = Provider::new(move |ip, request| {
            let mut reply = response(ip, request);
            if ip == PRIMARY {
                reply.answers.clear();
                reply.response_code = code;
            }
            reply
        });
        let recursor = resolver(&provider, binding(&[PRIMARY_NAME, SECONDARY_NAME]), false);
        handle(&recursor)
            .cached_name_server(&handle(&recursor).name_server_config(SECONDARY))
            .record_cancelled(Duration::from_millis(50));
        good(&lookup(&recursor, "host.bound.test.").await.unwrap());
        assert!(provider.called(PRIMARY));
        assert!(provider.called(SECONDARY));
        assert!(!provider.called(ROOT));
        provider.assert_tls_only();
    }
}

#[tokio::test]
async fn weak_connections_and_connections_with_another_trust_policy_are_not_reused() {
    for protocol in [Protocol::Udp, Protocol::Tls] {
        let provider = Provider::new(response);
        let recursor = resolver(&provider, binding(&[PRIMARY_NAME]), true);
        let handle = handle(&recursor);
        let server = Arc::new(NameServer::new(
            [(
                protocol,
                Connection {
                    ip: PLAIN,
                    state: provider.state.clone(),
                },
            )],
            handle.name_server_config(PRIMARY),
            &handle.pool_context.options,
            provider.clone(),
        ));
        let pool =
            NameServerPool::from_nameservers(vec![server.clone()], handle.pool_context.clone())
                .with_required_authentication();
        let reply = pool
            .lookup(query("one.bound.test."), DnsRequestOptions::default())
            .first_answer()
            .await
            .unwrap();
        good(&reply);
        assert_eq!(provider.state.calls.lock().unwrap().len(), 1);
        let reply = pool
            .lookup(query("two.bound.test."), DnsRequestOptions::default())
            .first_answer()
            .await
            .unwrap();
        good(&reply);
        assert_eq!(provider.state.calls.lock().unwrap().len(), 1);
        let other_cx = Arc::new(
            PoolContext::new(
                handle.pool_context.options.clone(),
                TlsConfig::new().unwrap(),
            )
            .with_server_tls_config(
                PRIMARY,
                Arc::from(PRIMARY_NAME),
                client_tls(ROGUE),
            ),
        );
        let other_pool =
            NameServerPool::from_nameservers(vec![server], other_cx).with_required_authentication();
        other_pool
            .lookup(query("three.bound.test."), DnsRequestOptions::default())
            .first_answer()
            .await
            .unwrap();
        let calls = provider.state.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_ne!(calls[0].identity, calls[1].identity);
        assert!(
            !provider
                .state
                .queries
                .lock()
                .unwrap()
                .iter()
                .any(|(ip, _)| *ip == PLAIN)
        );
    }
}

#[tokio::test]
async fn stalled_approved_connections_obey_the_pool_deadline() {
    let provider = Provider::new(response);
    provider.fail(PRIMARY, Failure::Stall);
    let cx = Arc::new(
        PoolContext::new(
            ResolverOpts {
                timeout: Duration::from_millis(30),
                server_ordering_strategy: ServerOrderingStrategy::UserProvidedOrder,
                ..Default::default()
            },
            TlsConfig::new().unwrap(),
        )
        .with_server_tls_config(PRIMARY, Arc::from(PRIMARY_NAME), client_tls(CA)),
    );
    let pool = NameServerPool::from_config(
        [NameServerConfig::tls(PRIMARY, Arc::from(PRIMARY_NAME))],
        cx,
        provider,
    )
    .with_required_authentication();
    let result = tokio::time::timeout(
        Duration::from_millis(300),
        pool.lookup(query("host.bound.test."), DnsRequestOptions::default())
            .first_answer(),
    )
    .await
    .expect("pool failed to enforce its deadline");
    assert!(matches!(result, Err(NetError::Timeout)));
}
