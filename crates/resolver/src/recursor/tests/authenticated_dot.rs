//! Real loopback TLS handshakes through the production connection provider.
//! Only the destination port is remapped, so tests need no privileged port 853.

use std::{
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use rustls::{
    CertificateError, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::TlsAcceptor;

use crate::{
    ConnectionProvider, PoolContext,
    config::{
        ConnectionConfig, OpportunisticEncryption, OpportunisticEncryptionConfig, ProtocolConfig,
    },
    net::{
        NetError,
        runtime::{RuntimeProvider, TokioRuntimeProvider},
        tls::default_provider,
    },
    proto::{
        op::{Message, Query, ResponseCode},
        rr::{Name, RData, Record, RecordType, rdata::SOA},
    },
    recursor::{
        DnssecPolicy, ForcedEncryptedAuthoritativeConfig, ForcedEncryptedAuthoritativePolicy,
        Recursor, RecursorOptions,
    },
};

const CA: &str = include_str!("../../../../../tests/test-data/authenticated-dot/ca.pem");
const ROGUE_CA: &str =
    include_str!("../../../../../tests/test-data/authenticated-dot/rogue-ca.pem");
const VALID: &str = include_str!("../../../../../tests/test-data/authenticated-dot/valid.pem");
const WRONG_NAME: &str =
    include_str!("../../../../../tests/test-data/authenticated-dot/wrong-name.pem");
const UNTRUSTED: &str =
    include_str!("../../../../../tests/test-data/authenticated-dot/untrusted.pem");
const EXPIRED: &str = include_str!("../../../../../tests/test-data/authenticated-dot/expired.pem");
const KEY: &str = include_str!("../../../../../tests/test-data/authenticated-dot/server.key");
const IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const EXPECTED_NAME: &str = "ns.auth-dot.test";

#[derive(Clone)]
struct RoutedRuntime {
    inner: TokioRuntimeProvider,
    tls: SocketAddr,
    plain: SocketAddr,
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
        server: SocketAddr,
        bind: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Tcp, io::Error>> + Send>> {
        let target = if server.port() == 853 {
            self.tls
        } else {
            self.plain
        };
        self.inner.connect_tcp(target, bind, timeout)
    }

    fn bind_udp(
        &self,
        _local: SocketAddr,
        _server: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Udp, io::Error>> + Send>> {
        // The independent controls below prove plaintext works. Any attempted
        // UDP selection by the protected recursor is recorded and fails the test.
        Box::pin(async { Err(io::Error::other("unexpected plaintext UDP selection")) })
    }
}

#[derive(Clone)]
struct ObservedProvider {
    runtime: RoutedRuntime,
    calls: Arc<Mutex<Vec<ConnectionConfig>>>,
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
        self.calls.lock().unwrap().push(config.clone());
        // Delegate the complete TLS handshake and verification to production
        // code; observation never replaces the TLS configuration or verifier.
        let future = self.runtime.new_connection(ip, config, cx)?;
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

fn answer(request: Message) -> Message {
    let query = request.queries[0].clone();
    let mut response = request.into_response();
    response.authoritative = true;
    response.metadata.authentic_data = false;
    if query.name.to_ascii().starts_with("missing.") {
        response.response_code = ResponseCode::NXDomain;
    } else if query.query_type == RecordType::A {
        response.add_answer(Record::from_rdata(
            query.name,
            30,
            RData::from(Ipv4Addr::new(192, 0, 2, 20)),
        ));
        return response;
    }
    response.add_authority(Record::from_rdata(
        Name::root(),
        30,
        RData::SOA(SOA::new(
            Name::from_ascii(EXPECTED_NAME).unwrap(),
            Name::from_ascii("hostmaster.auth-dot.test.").unwrap(),
            1,
            60,
            30,
            3600,
            30,
        )),
    ));
    response
}

async fn serve_dns<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S) -> io::Result<()> {
    loop {
        let length = stream.read_u16().await?;
        let mut bytes = vec![0; usize::from(length)];
        stream.read_exact(&mut bytes).await?;
        let request = Message::from_vec(&bytes).map_err(io::Error::other)?;
        let response = answer(request).to_vec().map_err(io::Error::other)?;
        stream
            .write_u16(u16::try_from(response.len()).unwrap())
            .await?;
        stream.write_all(&response).await?;
        stream.flush().await?;
    }
}

struct Fixture {
    tls: SocketAddr,
    plain: SocketAddr,
    names: Arc<Mutex<Vec<Option<String>>>>,
    handshakes: Arc<AtomicUsize>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Fixture {
    async fn start(certificate: &str) -> Self {
        let tls_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let plain_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let tls = tls_listener.local_addr().unwrap();
        let plain = plain_listener.local_addr().unwrap();
        let udp = UdpSocket::bind(plain).await.unwrap();
        let certificates = CertificateDer::pem_slice_iter(certificate.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = PrivateKeyDer::from_pem_slice(KEY.as_bytes()).unwrap();
        let server = ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certificates, key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server));
        let names = Arc::new(Mutex::new(vec![]));
        let handshakes = Arc::new(AtomicUsize::new(0));
        let seen_names = names.clone();
        let successes = handshakes.clone();
        let tls_task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            while let Ok((stream, _)) = tls_listener.accept().await {
                let acceptor = acceptor.clone();
                let names = seen_names.clone();
                let successes = successes.clone();
                connections.spawn(async move {
                    if let Ok(stream) = acceptor.accept(stream).await {
                        successes.fetch_add(1, Ordering::Relaxed);
                        names
                            .lock()
                            .unwrap()
                            .push(stream.get_ref().1.server_name().map(str::to_owned));
                        let _ = serve_dns(stream).await;
                    }
                });
            }
        });
        let plain_task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            while let Ok((stream, _)) = plain_listener.accept().await {
                connections.spawn(async move {
                    let _ = serve_dns(stream).await;
                });
            }
        });
        let udp_task = tokio::spawn(async move {
            let mut buffer = vec![0; 65535];
            while let Ok((length, peer)) = udp.recv_from(&mut buffer).await {
                let request = Message::from_vec(&buffer[..length]).unwrap();
                let response = answer(request).to_vec().unwrap();
                udp.send_to(&response, peer).await.unwrap();
            }
        });
        Self {
            tls,
            plain,
            names,
            handshakes,
            tasks: vec![tls_task, plain_task, udp_task],
        }
    }

    fn recursor(
        &self,
        ca: &str,
        opportunistic: bool,
    ) -> (Recursor<ObservedProvider>, ObservedProvider) {
        let config: ForcedEncryptedAuthoritativeConfig = serde_json::from_value(serde_json::json!({"servers":[{
            "name": format!("{EXPECTED_NAME}."), "address": IP.to_string(), "protocol":"dot", "trust_anchor":ca,
        }]})).unwrap();
        let policy = ForcedEncryptedAuthoritativePolicy::try_from(config).unwrap();
        let provider = ObservedProvider {
            runtime: RoutedRuntime {
                inner: TokioRuntimeProvider::new(),
                tls: self.tls,
                plain: self.plain,
            },
            calls: Arc::new(Mutex::new(vec![])),
            errors: Arc::new(Mutex::new(vec![])),
        };
        let mut options = RecursorOptions {
            deny_server: vec![],
            ..RecursorOptions::default()
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
            &[IP],
            DnssecPolicy::SecurityUnaware,
            None,
            options,
            provider.clone(),
            Some(Arc::new(policy)),
        )
        .unwrap();
        (recursor, provider)
    }

    async fn plaintext_controls(&self) {
        let query = Query::new(
            Name::from_ascii("host.auth-dot.test.").unwrap(),
            RecordType::A,
        );
        let mut request = Message::query();
        request.add_query(query);
        let request = request.to_vec().unwrap();
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        udp.send_to(&request, self.plain).await.unwrap();
        let mut buffer = [0; 4096];
        let (length, _) = tokio::time::timeout(Duration::from_secs(2), udp.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            Message::from_vec(&buffer[..length]).unwrap().answers.len(),
            1
        );
        let mut tcp = tokio::net::TcpStream::connect(self.plain).await.unwrap();
        tcp.write_u16(u16::try_from(request.len()).unwrap())
            .await
            .unwrap();
        tcp.write_all(&request).await.unwrap();
        let length = tokio::time::timeout(Duration::from_secs(2), tcp.read_u16())
            .await
            .unwrap()
            .unwrap();
        let mut response = vec![0; usize::from(length)];
        tcp.read_exact(&mut response).await.unwrap();
        assert_eq!(Message::from_vec(&response).unwrap().answers.len(), 1);
    }
}

async fn lookup(
    recursor: &Recursor<ObservedProvider>,
    name: &str,
) -> Result<Message, crate::recursor::RecursorError> {
    tokio::time::timeout(
        Duration::from_secs(5),
        recursor.resolve(
            Query::new(Name::from_ascii(name).unwrap(), RecordType::A),
            Instant::now(),
            false,
        ),
    )
    .await
    .expect("real DoT lookup exceeded test deadline")
}

fn assert_dot_only(provider: &ObservedProvider) {
    let calls = provider.calls.lock().unwrap();
    assert!(!calls.is_empty());
    for config in calls.iter() {
        assert_eq!(config.port, 853);
        assert_eq!(
            config.protocol,
            ProtocolConfig::Tls {
                server_name: Arc::from(EXPECTED_NAME)
            }
        );
    }
}

fn certificate_error(error: &NetError) -> Option<&CertificateError> {
    let error = match error {
        NetError::RustlsError(error) => error,
        NetError::Io(error) => error.get_ref()?.downcast_ref::<rustls::Error>()?,
        _ => return None,
    };
    match error {
        rustls::Error::InvalidCertificate(certificate) => Some(certificate),
        _ => None,
    }
}

#[tokio::test]
async fn valid_dot_authenticates_with_configured_name_and_anchor() {
    for opportunistic in [false, true] {
        let fixture = Fixture::start(VALID).await;
        fixture.plaintext_controls().await;
        let (recursor, provider) = fixture.recursor(CA, opportunistic);
        let response = lookup(&recursor, "host.auth-dot.test.").await.unwrap();
        assert_eq!(response.response_code, ResponseCode::NoError);
        assert!(
            response
                .answers
                .iter()
                .any(|r| r.data.ip_addr() == Some("192.0.2.20".parse().unwrap()))
        );
        assert!(
            !response.metadata.authentic_data,
            "DoT alone must not assert DNSSEC validation"
        );
        assert_dot_only(&provider);
        assert!(provider.errors.lock().unwrap().is_empty());
        assert!(fixture.handshakes.load(Ordering::Relaxed) > 0);
        assert!(
            fixture
                .names
                .lock()
                .unwrap()
                .iter()
                .all(|name| name.as_deref() == Some(EXPECTED_NAME))
        );
    }
}

#[tokio::test]
async fn invalid_certificates_fail_with_specific_verification_errors() {
    for opportunistic in [false, true] {
        for (certificate, anchor, expected) in [
            (WRONG_NAME, CA, "hostname"),
            (UNTRUSTED, CA, "issuer"),
            (EXPIRED, CA, "expiry"),
            (VALID, ROGUE_CA, "issuer"),
        ] {
            let fixture = Fixture::start(certificate).await;
            fixture.plaintext_controls().await;
            let (recursor, provider) = fixture.recursor(anchor, opportunistic);
            assert!(lookup(&recursor, "host.auth-dot.test.").await.is_err());
            assert_dot_only(&provider);
            let errors = provider.errors.lock().unwrap();
            assert!(!errors.is_empty());
            for error in errors.iter() {
                let matches = match (expected, certificate_error(error)) {
                    (
                        "hostname",
                        Some(
                            CertificateError::NotValidForName
                            | CertificateError::NotValidForNameContext { .. },
                        ),
                    ) => true,
                    ("issuer", Some(CertificateError::UnknownIssuer)) => true,
                    (
                        "expiry",
                        Some(CertificateError::Expired | CertificateError::ExpiredContext { .. }),
                    ) => true,
                    _ => false,
                };
                assert!(
                    matches,
                    "expected {expected} verification error, got {error:?}"
                );
            }
        }
    }
}

#[tokio::test]
async fn authenticated_nxdomain_remains_a_dns_result() {
    let fixture = Fixture::start(VALID).await;
    let (recursor, provider) = fixture.recursor(CA, false);
    let error = lookup(&recursor, "missing.auth-dot.test.")
        .await
        .unwrap_err();
    assert!(error.is_nx_domain(), "{error:?}");
    assert!(provider.errors.lock().unwrap().is_empty());
    assert_dot_only(&provider);
}
