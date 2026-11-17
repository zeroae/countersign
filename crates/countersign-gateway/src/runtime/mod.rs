mod broker;
mod config;
mod forward;
mod relay;
mod worker;

use self::{
    broker::{Broker, Credential, id, lease_request, utc_ms},
    config::{Config, Rule},
    relay::{EnforcedLeg, Guard},
    worker::{ChildHandle, CommandMessage, Reply, Start},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use countersign_gateway::{SharedIssuer, SidecarIssuer};
use countersign_protocol::{DestinationPolicy, Origin, wire::*};
use http_body_util::Empty;
use hyper::{Method, Request, Response, StatusCode, body::Incoming, header};
use hyper_util::rt::TokioIo;
use rustls::{
    RootCertStore, ServerConfig,
    client::{WebPkiServerVerifier, danger::ServerCertVerifier},
    crypto::ring::default_provider,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject};
use std::{
    collections::HashMap,
    convert::Infallible,
    error::Error,
    io,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use time::OffsetDateTime;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream, UnixStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    time::{Instant, timeout_at},
};
use x509_parser::prelude::{CertificateRevocationList, FromDer, parse_x509_certificate};
type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
fn invalid(message: &'static str) -> Box<dyn Error + Send + Sync> {
    io::Error::other(message).into()
}

type ReplyBody = Response<Empty<Bytes>>;

enum Issuer {
    Sidecar(Box<SidecarIssuer>),
    Shared(Box<SharedIssuer>),
}
struct Gateway {
    config: Config,
    policy: DestinationPolicy,
    issuer: Issuer,
    broker: Broker,
    children: Mutex<HashMap<Id, Slot>>,
}
struct Slot {
    worker: Id,
    workload: WorkloadBinding,
    expires: u64,
    process: ChildHandle,
    connections: Arc<Semaphore>,
    handshakes: Arc<Semaphore>,
}
struct Assignment {
    down: UnixStream,
    up: UnixStream,
    control: UnixStream,
    connection: OwnedSemaphorePermit,
    handshake: OwnedSemaphorePermit,
}

impl Gateway {
    fn attach(&self, activate: &Activate) -> Result<Assignment> {
        let grant = &activate.grant;
        let now = utc_ms()?;
        let mut children = self
            .children
            .lock()
            .map_err(|_| invalid("worker registry unavailable"))?;
        children.retain(|_, s| s.expires > now);
        let owned = children.values().filter(|s| {
            s.workload.integrator == grant.workload.integrator
                && s.workload.user == grant.workload.user
        });
        if owned
            .clone()
            .map(|s| 32 - s.connections.available_permits())
            .sum::<usize>()
            >= 128
            || owned
                .clone()
                .map(|s| 4 - s.handshakes.available_permits())
                .sum::<usize>()
                >= 16
        {
            return Err(invalid("user capacity exceeded"));
        }
        if !children.contains_key(&grant.grant) {
            if owned.count() >= 8 || children.len() >= 256 {
                return Err(invalid("worker capacity exceeded"));
            }
            let slot = Slot {
                worker: grant.worker.clone(),
                workload: grant.workload.clone(),
                expires: activate.expires_at_ms,
                process: ChildHandle::launch()?,
                connections: Arc::new(Semaphore::new(32)),
                handshakes: Arc::new(Semaphore::new(4)),
            };
            children.insert(grant.grant.clone(), slot);
        }
        let slot = children.get_mut(&grant.grant).expect("present");
        if slot.worker != grant.worker
            || slot.workload != grant.workload
            || slot.expires != activate.expires_at_ms
        {
            return Err(invalid("stale worker generation"));
        }
        let connection = slot.connections.clone().try_acquire_owned()?;
        let handshake = slot.handshakes.clone().try_acquire_owned()?;
        let [down, up, control] = slot.process.attach()?;
        Ok(Assignment {
            down,
            up,
            control,
            connection,
            handshake,
        })
    }
    fn credential(&self, req: &Request<Incoming>) -> Result<(Credential, WorkloadBinding)> {
        match &self.config.shared {
            Some(_) => {
                let values = req.headers().get_all(header::PROXY_AUTHORIZATION);
                let mut values = values.iter();
                let value = values
                    .next()
                    .ok_or_else(|| invalid("proxy authentication required"))?
                    .to_str()?;
                if values.next().is_some() {
                    return Err(invalid("duplicate proxy credential"));
                }
                Credential::ingress(
                    value
                        .strip_prefix("Bearer ")
                        .ok_or_else(|| invalid("invalid proxy credential"))?,
                )
            }
            None => Ok((
                Credential::File(
                    self.config
                        .workload_token
                        .clone()
                        .ok_or_else(|| invalid("no Workload credentials"))?,
                ),
                self.config
                    .workload
                    .clone()
                    .ok_or_else(|| invalid("no Workload binding"))?,
            )),
        }
    }
}

struct Connection {
    gateway: Arc<Gateway>,
    credential: Credential,
    response: GatewayActivation,
    origin: Origin,
    deadline: Instant,
    connection_id: Id,
}
struct PeerTrust {
    roots: Vec<CertificateDer<'static>>,
    crls: Vec<rustls_pki_types::CertificateRevocationListDer<'static>>,
}
impl PeerTrust {
    fn load(rule: &Rule) -> Result<Self> {
        Ok(Self {
            roots: config::anchors(&rule.roots)?,
            crls: config::crls(&rule.crls)?,
        })
    }
    fn validate(&self, host: &Origin, encoded: Vec<String>) -> Result<u64> {
        if encoded.is_empty() || encoded.len() > 16 {
            return Err(invalid("invalid upstream chain"));
        }
        let chain = encoded
            .into_iter()
            .map(|s| STANDARD.decode(s).map(CertificateDer::from))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut roots = RootCertStore::empty();
        for cert in &self.roots {
            roots.add(cert.clone())?;
        }
        let mut verifier = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(default_provider()),
        );
        if !self.crls.is_empty() {
            verifier = verifier
                .with_crls(self.crls.clone())
                .enforce_revocation_expiration();
        }
        let (leaf, intermediates) = chain
            .split_first()
            .ok_or_else(|| invalid("missing upstream identity"))?;
        verifier.build()?.verify_server_cert(
            leaf,
            intermediates,
            &ServerName::try_from(host.host())?,
            &[],
            UnixTime::now(),
        )?;
        let mut until = i64::MAX;
        for cert in chain {
            let (_, parsed) = parse_x509_certificate(&cert)
                .map_err(|_| invalid("invalid upstream certificate"))?;
            until = until.min(parsed.validity.not_after.timestamp());
        }
        for crl in &self.crls {
            let (_, parsed) =
                CertificateRevocationList::from_der(crl).map_err(|_| invalid("invalid CRL"))?;
            until = until.min(
                parsed
                    .next_update()
                    .ok_or_else(|| invalid("CRL expiry required"))?
                    .timestamp(),
            );
        }
        Ok(u64::try_from(until)?.saturating_mul(1000))
    }
}

fn http_response(status: StatusCode) -> ReplyBody {
    Response::builder()
        .status(status)
        .body(Empty::new())
        .expect("fixed response")
}
async fn connect_request(gateway: Arc<Gateway>, req: Request<Incoming>) -> ReplyBody {
    if req.method() != Method::CONNECT {
        return http_response(StatusCode::METHOD_NOT_ALLOWED);
    }
    let Ok((credential, workload)) = gateway.credential(&req) else {
        return http_response(StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    };
    let Some(authority) = req.uri().authority() else {
        return http_response(StatusCode::BAD_REQUEST);
    };
    let Ok(origin) = Origin::parse_connect(authority.as_str()) else {
        return http_response(StatusCode::BAD_REQUEST);
    };
    if req.uri().scheme().is_some()
        || req.uri().path_and_query().is_some()
        || req.headers().get_all(header::HOST).iter().any(|value| {
            value
                .to_str()
                .ok()
                .and_then(|s| Origin::parse(s).ok())
                .as_ref()
                != Some(&origin)
        })
    {
        return http_response(StatusCode::BAD_REQUEST);
    }
    let deadline = Instant::now() + Duration::from_secs(120);
    let Some(entry) = gateway.policy.resolve(&origin) else {
        return http_response(StatusCode::FORBIDDEN);
    };
    let Some(rule) = gateway
        .config
        .destinations
        .iter()
        .find(|r| r.id == entry.id())
    else {
        return http_response(StatusCode::FORBIDDEN);
    };
    let Ok(response) = gateway
        .broker
        .admit(&credential, &workload, &origin, deadline)
        .await
    else {
        return http_response(StatusCode::FORBIDDEN);
    };
    let activate = &response.activation;
    if !gateway.policy.covers(&activate.grant.scope, &origin) {
        return http_response(StatusCode::FORBIDDEN);
    }
    let grant = &activate.grant;
    let expiry = activate.expires_at_ms;
    let legs = tokio::try_join!(
        EnforcedLeg::acquire(
            &gateway.broker,
            &credential,
            lease_request(grant.clone(), Enforcer::Ingress),
            expiry,
            deadline
        ),
        EnforcedLeg::acquire(
            &gateway.broker,
            &credential,
            lease_request(grant.clone(), Enforcer::Egress),
            expiry,
            deadline
        )
    );
    let Ok((ingress, egress)) = legs else {
        eprintln!("Gateway lease admission unavailable");
        return http_response(StatusCode::SERVICE_UNAVAILABLE);
    };
    let Ok(trust) = PeerTrust::load(rule) else {
        return http_response(StatusCode::BAD_GATEWAY);
    };
    let target = timeout_at(deadline, async {
        let pinned = config::resolve_target(&origin, rule, &gateway.config.denied_networks).await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(TcpStream::connect(pinned).await?)
    })
    .await;
    let Ok(Ok(target)) = target else {
        return http_response(StatusCode::BAD_GATEWAY);
    };
    if ingress.guard.check().is_err() || egress.guard.check().is_err() {
        return http_response(StatusCode::SERVICE_UNAVAILABLE);
    }
    let assignment = match gateway.attach(activate) {
        Ok(slot) => slot,
        Err(error) => {
            eprintln!("Gateway worker admission failed: {error}");
            return http_response(StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    let upgraded = hyper::upgrade::on(req);
    let connection = Connection {
        gateway,
        credential,
        response,
        origin,
        deadline,
        connection_id: id(),
    };
    tokio::spawn(async move {
        let Ok(Ok(downstream)) = timeout_at(deadline, upgraded).await else {
            return;
        };
        let guards = [ingress.guard.clone(), egress.guard.clone()];
        let assignment = assignment;
        let _connection = assignment.connection;
        let (stage, result) = tokio::select! {
            biased;
            r=ingress.relay(TokioIo::new(downstream),assignment.down,&connection.gateway.broker,&connection.credential,expiry)=>("ingress",r),
            r=egress.relay(target,assignment.up,&connection.gateway.broker,&connection.credential,expiry)=>("egress",r),
            r=connection.handshake(assignment.control,trust,guards,assignment.handshake)=>("handshake",r),
        };
        if let Err(error) = result {
            eprintln!(
                "Gateway connection {} ended at {stage}: {error}",
                connection.connection_id.as_str()
            );
        }
    });
    http_response(StatusCode::OK)
}

impl Connection {
    fn check(&self, guards: &[Guard; 2]) -> Result<()> {
        if Instant::now() >= self.deadline {
            return Err(invalid("handshake timed out"));
        }
        guards[0].check()?;
        guards[1].check()
    }
    async fn handshake(
        &self,
        mut control: UnixStream,
        trust: PeerTrust,
        guards: [Guard; 2],
        permit: OwnedSemaphorePermit,
    ) -> Result<()> {
        let grant = &self.response.activation.grant;
        let expiry = self.response.activation.expires_at_ms;
        let evidence_deadline = timeout_at(self.deadline, async {
            let start = Start {
                origin: self.origin.clone(),
                activation: self.response.clone(),
                roots: trust.roots.iter().map(|r| STANDARD.encode(r)).collect(),
                crls: trust.crls.iter().map(|c| STANDARD.encode(c)).collect(),
            };
            worker::send(&mut control, &start).await?;
            let CommandMessage::Csr(csr) = worker::receive(&mut control).await? else {
                return Err(invalid("expected certificate request"));
            };
            self.check(&guards)?;
            let deadline = OffsetDateTime::from_unix_timestamp(i64::try_from(expiry / 1000)?)?;
            let csr = STANDARD.decode(csr)?;
            let chain = match &self.gateway.issuer {
                Issuer::Sidecar(s) => vec![s.issue(&grant.scope, &self.origin, deadline, &csr)?],
                Issuer::Shared(s) => {
                    s.issue(
                        &grant.scope,
                        &self.origin,
                        deadline,
                        &csr,
                        &format!("{}/{}", grant.grant.as_str(), grant.grant_version),
                    )
                    .await?
                }
            };
            self.check(&guards)?;
            worker::send(
                &mut control,
                &Reply::Certificates(chain.iter().map(|c| STANDARD.encode(c)).collect()),
            )
            .await?;
            let CommandMessage::Sign { tls, scheme, input } = worker::receive(&mut control).await?
            else {
                return Err(invalid("expected signing request"));
            };
            self.check(&guards)?;
            let op = Operation {
                grant: grant.clone(),
                host: self.origin.clone(),
                tls_connection: self.connection_id.clone(),
                operation: id(),
            };
            let bound = expiry.min(
                utc_ms()?.saturating_add(
                    self.deadline
                        .saturating_duration_since(Instant::now())
                        .as_millis() as u64,
                ),
            );
            let sign = Sign {
                binding: op.clone(),
                tls,
                scheme,
                certificate_verify: SigningInput::new(STANDARD.decode(input)?)?,
                deadline_ms: bound,
            };
            let mut cancel = CancelOnDrop {
                broker: self.gateway.clone(),
                credential: self.credential.clone(),
                operation: Some(op.clone()),
            };
            let result = self
                .gateway
                .broker
                .call(
                    "sign",
                    &self.credential,
                    GatewayToBroker::Sign(sign),
                    self.deadline,
                )
                .await?;
            let BrokerToGateway::Signed(result) = result else {
                return Err(invalid("signing refused"));
            };
            if result.binding != op {
                return Err(invalid("signing reply binding mismatch"));
            }
            self.check(&guards)?;
            worker::send(
                &mut control,
                &Reply::Signature(STANDARD.encode(result.signature.as_slice())),
            )
            .await?;
            cancel.operation.take();
            let CommandMessage::Ready { peer_chain } = worker::receive(&mut control).await? else {
                return Err(invalid("expected upstream confirmation"));
            };
            let cap = trust
                .validate(&self.origin, peer_chain)?
                .min(expiry)
                .saturating_sub(self.gateway.config.clock_uncertainty_ms);
            let wall = utc_ms()?;
            if cap <= wall {
                return Err(invalid("upstream validation expired"));
            }
            self.check(&guards)?;
            for guard in &guards {
                guard.cap(cap)?;
            }
            worker::send(&mut control, &Reply::Proceed).await?;
            Ok(Instant::now() + Duration::from_millis(cap - wall))
        })
        .await??;
        drop(permit);
        tokio::time::sleep_until(evidence_deadline).await;
        Ok(())
    }
}

struct CancelOnDrop {
    broker: Arc<Gateway>,
    credential: Credential,
    operation: Option<Operation>,
}
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if let Some(op) = self.operation.take() {
            let gateway = self.broker.clone();
            let credential = self.credential.clone();
            tokio::spawn(async move {
                let _ = gateway
                    .broker
                    .call(
                        "cancel",
                        &credential,
                        GatewayToBroker::Cancel(op),
                        Instant::now() + Duration::from_secs(2),
                    )
                    .await;
            });
        }
    }
}
async fn proxy<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: T,
    gateway: Arc<Gateway>,
) {
    let service = hyper::service::service_fn(move |req| {
        let g = gateway.clone();
        async move { Ok::<_, Infallible>(connect_request(g, req).await) }
    });
    let _ = hyper::server::conn::http1::Builder::new()
        .max_headers(32)
        .max_buf_size(16384)
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10))
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades()
        .await;
}

pub async fn run(args: &[String]) -> Result<()> {
    if args == ["grant-worker"] {
        return worker::serve();
    }
    let [verb, path] = args else {
        return Err(invalid("usage: countersign-gateway serve|env CONFIG.json"));
    };
    let config = Config::load(Path::new(path))?;
    if verb == "env" {
        println!("{}", config.env()?);
        return Ok(());
    }
    if verb != "serve" {
        return Err(invalid("unrecognized Gateway command"));
    }
    let policy = config.policy()?;
    let broker = Broker::new(&config)?;
    let (issuer, tls) = if let Some(shared) = &config.shared {
        let issuer = SharedIssuer::open(shared.ca.clone(), policy.clone()).await?;
        let mut tls = ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(
                config::anchors(&shared.listener_cert)?,
                PrivateKeyDer::from_pem_file(&shared.listener_key)?,
            )?;
        tls.send_tls13_tickets = 0;
        tls.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        (
            Issuer::Shared(Box::new(issuer)),
            Some(tokio_rustls::TlsAcceptor::from(Arc::new(tls))),
        )
    } else {
        let issuer = SidecarIssuer::new(
            policy.clone(),
            OffsetDateTime::now_utc() + time::Duration::days(366),
        )?;
        config::publish_ca(&config.ca_output, &issuer.public_cert_pem())?;
        (Issuer::Sidecar(Box::new(issuer)), None)
    };
    let listener = TcpListener::bind(config.listen).await?;
    let gateway = Arc::new(Gateway {
        config,
        issuer,
        broker,
        policy,
        children: Mutex::new(HashMap::new()),
    });
    let cleanup = gateway.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            let now = utc_ms().unwrap_or(u64::MAX);
            if let Ok(mut children) = cleanup.children.lock() {
                children.retain(|_, s| s.expires > now);
            }
        }
    });
    let permits = Arc::new(Semaphore::new(512));
    loop {
        let permit = permits.clone().acquire_owned().await?;
        let (stream, _) = listener.accept().await?;
        let gateway = gateway.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Some(tls) = tls {
                if let Ok(Ok(stream)) =
                    tokio::time::timeout(Duration::from_secs(10), tls.accept(stream)).await
                {
                    proxy(stream, gateway).await;
                }
            } else {
                proxy(stream, gateway).await;
            }
        });
    }
}
