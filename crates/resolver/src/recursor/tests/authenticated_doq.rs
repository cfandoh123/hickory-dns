//! Real QUIC handshakes and DNS streams through the production connection provider.
//! The socket adapter changes only loopback addresses/ports, never TLS settings.
//! Reachable plaintext and opportunistic QUIC controls rule out false rejection
//! from a broken authority. Mock tests cover referrals, retry and cache decisions.

use std::{
    collections::HashMap,
    future::Future,
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use quinn::{
    AsyncUdpSocket, Runtime,
    crypto::rustls::{HandshakeData, QuicServerConfig},
};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::{JoinHandle, JoinSet},
};

use super::authenticated_dot::{
    CA, EXPECTED_NAME, EXPIRED, Fixture as PlaintextFixture, IP, KEY, ROGUE_CA, UNTRUSTED, VALID,
    WRONG_NAME, answer,
};
use crate::{
    ConnectionProvider, PoolContext, TlsConfig,
    config::{
        ConnectionConfig, NameServerConfig, OpportunisticEncryption, OpportunisticEncryptionConfig,
        ProtocolConfig, ResolverOpts,
    },
    net::{
        NetError,
        runtime::{QuicSocketBinder, RuntimeProvider, TokioRuntimeProvider},
        tls::default_provider,
        xfer::{DnsHandle, FirstAnswer, Protocol},
    },
    proto::{
        op::{DnsRequestOptions, Message, Query, ResponseCode},
        rr::{Name, RecordType},
    },
    recursor::{
        DnssecPolicy, ForcedEncryptedAuthoritativeConfig, ForcedEncryptedAuthoritativePolicy,
        Recursor, RecursorOptions,
    },
};

/// Translate datagram destinations and source metadata while preserving QUIC bytes.
#[derive(Debug)]
struct RoutedSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    logical: SocketAddr,
    target: SocketAddr,
}
impl AsyncUdpSocket for RoutedSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        self.inner.clone().create_io_poller()
    }
    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        assert_eq!(transmit.destination, self.logical);
        self.inner.try_send(&quinn::udp::Transmit {
            destination: self.target,
            ..*transmit
        })
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        match self.inner.poll_recv(cx, bufs, meta) {
            Poll::Ready(Ok(count)) => {
                for item in &mut meta[..count] {
                    assert_eq!(item.addr, self.target);
                    item.addr = self.logical;
                }
                Poll::Ready(Ok(count))
            }
            other => other,
        }
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }
    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }
    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[derive(Clone)]
struct RoutedRuntime {
    inner: TokioRuntimeProvider,
    routes: Arc<HashMap<IpAddr, SocketAddr>>,
    plaintext: Arc<AtomicUsize>,
    no_binder: bool,
    bind_error: bool,
}
impl RuntimeProvider for RoutedRuntime {
    type Handle = <TokioRuntimeProvider as RuntimeProvider>::Handle;
    type Timer = <TokioRuntimeProvider as RuntimeProvider>::Timer;
    type Udp = <TokioRuntimeProvider as RuntimeProvider>::Udp;
    type Tcp = <TokioRuntimeProvider as RuntimeProvider>::Tcp;
    fn create_handle(&self) -> Self::Handle {
        self.inner.create_handle()
    }
    fn connect_tcp(
        &self,
        _server: SocketAddr,
        _bind: Option<SocketAddr>,
        _timeout: Option<Duration>,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Tcp, io::Error>> + Send>> {
        self.plaintext.fetch_add(1, Ordering::Relaxed);
        Box::pin(async { Err(io::Error::other("unexpected TCP/DoT fallback")) })
    }
    fn bind_udp(
        &self,
        _local: SocketAddr,
        _server: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Udp, io::Error>> + Send>> {
        self.plaintext.fetch_add(1, Ordering::Relaxed);
        Box::pin(async { Err(io::Error::other("unexpected plaintext UDP fallback")) })
    }
    fn quic_binder(&self) -> Option<&dyn QuicSocketBinder> {
        if self.no_binder { None } else { Some(self) }
    }
}
impl QuicSocketBinder for RoutedRuntime {
    fn bind_quic(
        &self,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Result<Arc<dyn AsyncUdpSocket>, io::Error> {
        if self.bind_error {
            return Err(io::Error::other("injected bind failure"));
        }
        let socket = std::net::UdpSocket::bind(local)?;
        socket.set_nonblocking(true)?;
        Ok(Arc::new(RoutedSocket {
            inner: quinn::TokioRuntime.wrap_udp_socket(socket)?,
            logical: remote,
            target: self.routes[&remote.ip()],
        }))
    }
}

#[derive(Clone)]
struct ObservedProvider {
    runtime: RoutedRuntime,
    calls: Arc<Mutex<Vec<(IpAddr, ConnectionConfig)>>>,
    errors: Arc<Mutex<Vec<NetError>>>,
}
impl ConnectionProvider for ObservedProvider {
    type Conn = <RoutedRuntime as ConnectionProvider>::Conn;
    type FutureConn = Pin<Box<dyn Future<Output = Result<Self::Conn, NetError>> + Send>>;
    type RuntimeProvider = RoutedRuntime;
    fn runtime_provider(&self) -> &Self::RuntimeProvider {
        &self.runtime
    }
    fn new_connection(
        &self,
        ip: IpAddr,
        config: &ConnectionConfig,
        cx: &PoolContext,
    ) -> Result<Self::FutureConn, NetError> {
        self.calls.lock().unwrap().push((ip, config.clone()));
        let future = match self.runtime.new_connection(ip, config, cx) {
            Ok(future) => future,
            Err(error) => {
                self.errors.lock().unwrap().push(error.clone());
                return Err(error);
            }
        };
        let errors = self.errors.clone();
        Ok(Box::pin(async move {
            let result = future.await;
            if let Err(error) = &result {
                errors.lock().unwrap().push(error.clone());
            }
            result
        }))
    }
}

fn server_config(certificate: &str) -> quinn::ServerConfig {
    let certificates = CertificateDer::pem_slice_iter(certificate.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(KEY.as_bytes()).unwrap();
    let mut tls = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .unwrap();
    tls.alpn_protocols = vec![b"doq".to_vec()];
    quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap()))
}

fn client_tls(ca: &str) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(ca.as_bytes()).unwrap())
        .unwrap();
    rustls::ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

struct Fixture {
    target: SocketAddr,
    endpoint: quinn::Endpoint,
    names: Arc<Mutex<Vec<String>>>,
    handshakes: Arc<AtomicUsize>,
    connections: Arc<Mutex<Vec<quinn::Connection>>>,
    task: JoinHandle<()>,
    plain: PlaintextFixture,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"test finished");
        self.task.abort();
    }
}
impl Fixture {
    async fn start(certificate: &str) -> Self {
        let server = server_config(certificate);
        let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        socket.set_nonblocking(true).unwrap();
        let endpoint = quinn::Endpoint::new(
            Default::default(),
            Some(server),
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        let target = endpoint.local_addr().unwrap();
        let incoming = endpoint.clone();
        let names = Arc::new(Mutex::new(vec![]));
        let seen = names.clone();
        let handshakes = Arc::new(AtomicUsize::new(0));
        let count = handshakes.clone();
        let connections = Arc::new(Mutex::new(vec![]));
        let retained = connections.clone();
        let task = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            while let Some(connecting) = incoming.accept().await {
                let seen = seen.clone();
                let count = count.clone();
                let retained = retained.clone();
                tasks.spawn(async move {
                    let Ok(connection) = connecting.await else {
                        return;
                    };
                    let data = connection
                        .handshake_data()
                        .unwrap()
                        .downcast::<HandshakeData>()
                        .unwrap();
                    assert_eq!(data.protocol.as_deref(), Some(b"doq".as_slice()));
                    seen.lock()
                        .unwrap()
                        .push(data.server_name.unwrap_or_default());
                    count.fetch_add(1, Ordering::Relaxed);
                    retained.lock().unwrap().push(connection.clone());
                    while let Ok((mut send, mut receive)) = connection.accept_bi().await {
                        let length = receive.read_u16().await.unwrap();
                        let mut bytes = vec![0; usize::from(length)];
                        receive.read_exact(&mut bytes).await.unwrap();
                        assert!(receive.read_to_end(1).await.unwrap().is_empty());
                        let request = Message::from_vec(&bytes).unwrap();
                        assert_eq!(request.id, 0, "DoQ query IDs must be zero");
                        let response = answer(request).to_vec().unwrap();
                        send.write_u16(u16::try_from(response.len()).unwrap())
                            .await
                            .unwrap();
                        send.write_all(&response).await.unwrap();
                        send.finish().unwrap();
                    }
                });
                while let Some(result) = tasks.try_join_next() {
                    result.unwrap();
                }
            }
        });
        Self {
            target,
            endpoint,
            names,
            handshakes,
            connections,
            task,
            plain: PlaintextFixture::start(VALID).await,
        }
    }

    /// Exercise the same server over opportunistic QUIC without a required policy.
    async fn opportunistic_control(&self) {
        let mut tls = TlsConfig::new().unwrap();
        tls.insecure_skip_verify();
        let cx = PoolContext::new(ResolverOpts::default(), tls);
        let mut config = NameServerConfig::quic(IP, Arc::from(EXPECTED_NAME))
            .connections
            .remove(0);
        config.port = self.target.port();
        let runtime = TokioRuntimeProvider::new();
        let client = runtime
            .new_connection(IP, &config, &cx)
            .unwrap()
            .await
            .unwrap();
        let response = client
            .lookup(
                query("control.auth-dot.test."),
                DnsRequestOptions::default(),
            )
            .first_answer()
            .await
            .unwrap();
        assert_eq!(response.answers.len(), 1);
    }
}

fn query(name: &str) -> Query {
    Query::new(Name::from_ascii(name).unwrap(), RecordType::A)
}

fn resolver(
    routes: HashMap<IpAddr, SocketAddr>,
    anchor: &str,
    opportunistic: bool,
    referrals: bool,
) -> (Recursor<ObservedProvider>, ObservedProvider) {
    let mut addresses: Vec<_> = routes.keys().copied().collect();
    addresses.sort();
    let config: ForcedEncryptedAuthoritativeConfig = serde_json::from_value(serde_json::json!({
        "servers": addresses.iter().map(|ip| serde_json::json!({
            "name": EXPECTED_NAME, "address": ip.to_string(), "protocol":"doq", "trust_anchor":anchor,
        })).collect::<Vec<_>>(),
        "authenticated_referrals":referrals,
    })).unwrap();
    let policy = ForcedEncryptedAuthoritativePolicy::try_from(config).unwrap();
    let provider = ObservedProvider {
        runtime: RoutedRuntime {
            inner: TokioRuntimeProvider::new(),
            routes: Arc::new(routes),
            plaintext: Arc::new(AtomicUsize::new(0)),
            no_binder: false,
            bind_error: false,
        },
        calls: Arc::new(Mutex::new(vec![])),
        errors: Arc::new(Mutex::new(vec![])),
    };
    let mut options = RecursorOptions {
        deny_server: vec![],
        connect_timeout_ms: Some(300),
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
    let recursor = Recursor::new_with_policy(
        &addresses,
        DnssecPolicy::SecurityUnaware,
        None,
        options,
        provider.clone(),
        Some(Arc::new(policy)),
    )
    .unwrap();
    (recursor, provider)
}

async fn lookup(
    recursor: &Recursor<ObservedProvider>,
    name: &str,
) -> Result<Message, crate::recursor::RecursorError> {
    tokio::time::timeout(
        Duration::from_secs(5),
        recursor.resolve(query(name), Instant::now(), false),
    )
    .await
    .expect("real DoQ lookup exceeded test deadline")
}
fn assert_doq_only(provider: &ObservedProvider) {
    let calls = provider.calls.lock().unwrap();
    assert!(!calls.is_empty());
    for (_, config) in calls.iter() {
        assert_eq!(config.port, 853);
        assert_eq!(
            config.protocol,
            ProtocolConfig::Quic {
                server_name: Arc::from(EXPECTED_NAME)
            }
        );
    }
    assert_eq!(provider.runtime.plaintext.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn valid_doq_authenticates_and_reuses_only_the_verified_connection() {
    for opportunistic in [false, true] {
        for referrals in [false, true] {
            let fixture = Fixture::start(VALID).await;
            fixture.plain.plaintext_controls().await;
            let (recursor, provider) = resolver(
                HashMap::from([(IP, fixture.target)]),
                CA,
                opportunistic,
                referrals,
            );
            for name in ["one.auth-dot.test.", "two.auth-dot.test."] {
                let response = lookup(&recursor, name).await.unwrap();
                assert_eq!(response.response_code, ResponseCode::NoError);
                assert!(
                    response
                        .answers
                        .iter()
                        .any(|r| r.data.ip_addr() == Some("192.0.2.20".parse().unwrap()))
                );
                assert!(
                    !response.metadata.authentic_data,
                    "DoQ is not DNSSEC validation"
                );
            }
            assert_doq_only(&provider);
            assert!(provider.errors.lock().unwrap().is_empty());
            assert_eq!(fixture.handshakes.load(Ordering::Relaxed), 1);
            assert_eq!(fixture.names.lock().unwrap().as_slice(), [EXPECTED_NAME]);
            assert_eq!(provider.calls.lock().unwrap().len(), 1);
        }
    }
}

#[tokio::test]
async fn invalid_doq_certificates_fail_without_plaintext_or_dot_fallback() {
    for opportunistic in [false, true] {
        for (certificate, anchor, alert) in [
            (WRONG_NAME, CA, 42),
            (UNTRUSTED, CA, 48),
            (EXPIRED, CA, 45),
            (VALID, ROGUE_CA, 48),
        ] {
            let fixture = Fixture::start(certificate).await;
            fixture.plain.plaintext_controls().await;
            fixture.opportunistic_control().await;
            let (recursor, provider) = resolver(
                HashMap::from([(IP, fixture.target)]),
                anchor,
                opportunistic,
                false,
            );
            assert!(
                lookup(&recursor, "host.auth-dot.test.")
                    .await
                    .unwrap_err()
                    .is_security_failure()
            );
            assert_doq_only(&provider);
            let errors = provider.errors.lock().unwrap();
            assert!(!errors.is_empty());
            for error in errors.iter() {
                let NetError::RequiredTransportFailure { source, .. } = error else {
                    panic!("{error:?}");
                };
                let NetError::QuinnConnection(quinn::ConnectionError::TransportError(error)) =
                    source.as_ref()
                else {
                    panic!("expected QUIC certificate rejection: {source:?}");
                };
                assert_eq!(u64::from(error.code), 0x100 + alert, "{error:?}");
            }
        }
    }
}

#[tokio::test]
async fn stalled_doq_handshake_is_a_bounded_security_failure() {
    let sink = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let (recursor, provider) = resolver(
        HashMap::from([(IP, sink.local_addr().unwrap())]),
        CA,
        true,
        false,
    );
    let start = Instant::now();
    assert!(
        lookup(&recursor, "host.auth-dot.test.")
            .await
            .unwrap_err()
            .is_security_failure()
    );
    assert!(start.elapsed() < Duration::from_secs(2));
    let mut packet = [0; 2048];
    assert!(
        sink.try_recv(&mut packet).unwrap() > 0,
        "QUIC handshake was never attempted"
    );
    assert_doq_only(&provider);
    assert!(provider.errors.lock().unwrap().iter().all(|error| matches!(error,
        NetError::RequiredTransportFailure { source, .. } if matches!(source.as_ref(), NetError::Timeout))));
}

#[tokio::test]
async fn authenticated_doq_nxdomain_remains_a_dns_result() {
    let fixture = Fixture::start(VALID).await;
    let (recursor, provider) = resolver(HashMap::from([(IP, fixture.target)]), CA, false, false);
    assert!(
        lookup(&recursor, "missing.auth-dot.test.")
            .await
            .unwrap_err()
            .is_nx_domain()
    );
    assert_doq_only(&provider);
    assert!(provider.errors.lock().unwrap().is_empty());
}

#[tokio::test]
async fn required_doq_rejects_wrong_protocol_port_name_and_unavailable_runtime() {
    let (_, provider) = resolver(
        HashMap::from([(IP, "127.0.0.1:1".parse().unwrap())]),
        CA,
        false,
        false,
    );
    let tls = client_tls(CA);
    let cx = PoolContext::new(ResolverOpts::default(), TlsConfig::new().unwrap())
        .with_server_tls_config(IP, Arc::from(EXPECTED_NAME), Protocol::Quic, tls);
    let good = NameServerConfig::quic(IP, Arc::from(EXPECTED_NAME))
        .connections
        .remove(0);
    let mut wrong_port = good.clone();
    wrong_port.port = 8853;
    for config in [
        NameServerConfig::udp(IP).connections.remove(0),
        NameServerConfig::tcp(IP).connections.remove(0),
        NameServerConfig::tls(IP, Arc::from(EXPECTED_NAME))
            .connections
            .remove(0),
        NameServerConfig::quic(IP, Arc::from("wrong.test"))
            .connections
            .remove(0),
        wrong_port,
    ] {
        assert!(matches!(
            provider.runtime.new_connection(IP, &config, &cx),
            Err(NetError::SecurityPolicy(_))
        ));
    }
    for (no_binder, bind_error) in [(true, false), (false, true)] {
        let mut runtime = provider.runtime.clone();
        runtime.no_binder = no_binder;
        runtime.bind_error = bind_error;
        assert!(matches!(
            runtime.new_connection(IP, &good, &cx),
            Err(NetError::RequiredTransportFailure { .. })
        ));
    }
    assert_eq!(provider.runtime.plaintext.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn rejected_quic_certificate_retries_only_an_approved_authenticated_backup() {
    let rejected = Fixture::start(UNTRUSTED).await;
    let backup = Fixture::start(VALID).await;
    let second: IpAddr = "127.0.0.2".parse().unwrap();
    let (_, provider) = resolver(
        HashMap::from([(IP, rejected.target), (second, backup.target)]),
        CA,
        true,
        false,
    );
    let mut cx = PoolContext::new(
        ResolverOpts {
            num_concurrent_reqs: 1,
            connect_timeout: Duration::from_millis(300),
            server_ordering_strategy: crate::config::ServerOrderingStrategy::UserProvidedOrder,
            ..Default::default()
        },
        TlsConfig::new().unwrap(),
    );
    for ip in [IP, second] {
        cx =
            cx.with_server_tls_config(ip, Arc::from(EXPECTED_NAME), Protocol::Quic, client_tls(CA));
    }
    let pool = crate::name_server_pool::NameServerPool::from_config(
        [IP, second].map(|ip| NameServerConfig::quic(ip, Arc::from(EXPECTED_NAME))),
        Arc::new(cx),
        provider.clone(),
    )
    .with_required_authentication();
    let response = tokio::time::timeout(
        Duration::from_secs(2),
        pool.lookup(query("backup.auth-dot.test."), DnsRequestOptions::default())
            .first_answer(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.answers.len(), 1);
    assert_eq!(
        provider
            .calls
            .lock()
            .unwrap()
            .iter()
            .map(|(ip, _)| *ip)
            .collect::<Vec<_>>(),
        [IP, second]
    );
    assert!(
        provider
            .errors
            .lock()
            .unwrap()
            .iter()
            .any(|error| matches!(error,
        NetError::RequiredTransportFailure { server, .. } if *server == IP))
    );
    assert_eq!(backup.handshakes.load(Ordering::Relaxed), 1);
    assert_doq_only(&provider);
}

#[tokio::test]
async fn quic_reconnect_authenticates_again_and_rejects_a_changed_server_certificate() {
    let fixture = Fixture::start(VALID).await;
    let (recursor, provider) = resolver(HashMap::from([(IP, fixture.target)]), CA, true, false);
    lookup(&recursor, "before.auth-dot.test.").await.unwrap();
    assert_eq!(fixture.handshakes.load(Ordering::Relaxed), 1);
    fixture
        .endpoint
        .set_server_config(Some(server_config(WRONG_NAME)));
    // Close just this verified session, keeping the authority reachable for a
    // new handshake. A resumed/recreated client must still check its certificate.
    for connection in fixture.connections.lock().unwrap().iter() {
        connection.close(0u32.into(), b"rotate test certificate");
    }
    let error = lookup(&recursor, "after.auth-dot.test.").await.unwrap_err();
    assert!(error.is_security_failure(), "{error:?}");
    assert!(provider.calls.lock().unwrap().len() >= 2);
    assert!(!provider.errors.lock().unwrap().is_empty());
    assert_doq_only(&provider);
    fixture.opportunistic_control().await;
}
