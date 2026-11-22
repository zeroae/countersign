mod broker;
mod config;
mod egress;
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
    sync::{OwnedSemaphorePermit, Semaphore, watch},
    time::{Instant, timeout_at},
};
use x509_parser::prelude::parse_x509_certificate;
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
    observations: Arc<Semaphore>,
    children: Mutex<HashMap<Id, Slot>>,
}
struct Slot {
    requests: Arc<Semaphore>,
    user_requests: Arc<Semaphore>,
    binding: GrantBinding,
    expires: u64,
    process: Option<ChildHandle>,
    fence: watch::Sender<bool>,
    connections: Arc<Semaphore>,
    handshakes: Arc<Semaphore>,
}
struct Assignment {
    fence: watch::Receiver<bool>,
    down: UnixStream,
    up: UnixStream,
    control: UnixStream,
    connection: OwnedSemaphorePermit,
    handshake: OwnedSemaphorePermit,
    requests: [Arc<Semaphore>; 2],
}

impl Gateway {
    fn attach(
        self: &Arc<Self>,
        activate: &Activate,
        credential: &Credential,
    ) -> Result<Assignment> {
        let grant = &activate.grant;
        let now = utc_ms()?;
        let mut children = self
            .children
            .lock()
            .map_err(|_| invalid("worker registry unavailable"))?;
        children.retain(|_, s| s.expires > now);
        let owned = children.values().filter(|s| {
            s.process.is_some()
                && s.binding.workload.integrator == grant.workload.integrator
                && s.binding.workload.user == grant.workload.user
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
            return Err(Capacity.into());
        }
        if !children.contains_key(&grant.grant) {
            if owned.clone().count() >= 8
                || children.values().filter(|s| s.process.is_some()).count() >= 256
                || children.len() >= 4096
            {
                return Err(Capacity.into());
            }
            let (fence, closed) = watch::channel(false);
            let (process, exit) = ChildHandle::launch(self.config.worker_sandbox)?;
            let slot = Slot {
                fence,
                requests: Arc::new(Semaphore::new(32)),
                user_requests: owned
                    .clone()
                    .next()
                    .map(|s| s.user_requests.clone())
                    .unwrap_or_else(|| Arc::new(Semaphore::new(128))),
                binding: grant.clone(),
                expires: activate.expires_at_ms,
                process: Some(process),
                connections: Arc::new(Semaphore::new(32)),
                handshakes: Arc::new(Semaphore::new(4)),
            };
            children.insert(grant.grant.clone(), slot);
            tokio::spawn(self.clone().watch_worker(grant.clone(), exit));
            tokio::spawn(self.clone().watch_retirement(
                grant.clone(),
                credential.clone(),
                activate.expires_at_ms,
                closed,
            ));
        }
        let slot = children.get_mut(&grant.grant).expect("present");
        if &slot.binding != grant || slot.expires != activate.expires_at_ms {
            return Err(invalid("stale worker generation"));
        }
        let connection = slot.connections.clone().try_acquire_owned()?;
        let handshake = slot.handshakes.clone().try_acquire_owned()?;
        let child = slot
            .process
            .as_mut()
            .ok_or_else(|| invalid("worker fenced"))?;
        let [down, up, control] = match child.attach() {
            Ok(streams) => streams,
            Err(error) => {
                slot.fence.send_replace(true);
                slot.process.take();
                return Err(error);
            }
        };
        Ok(Assignment {
            fence: slot.fence.subscribe(),
            down,
            up,
            control,
            connection,
            handshake,
            requests: [slot.requests.clone(), slot.user_requests.clone()],
        })
    }
    fn fence(&self, grant: &GrantBinding) {
        if let Ok(mut children) = self.children.lock()
            && let Some(slot) = children.get_mut(&grant.grant)
            && &slot.binding == grant
        {
            slot.fence.send_replace(true);
            slot.process.take(); // kill-on-drop, reaped asynchronously
        }
    }

    /// A grant worker that ends on its own, whatever the cause, has failed:
    /// its grant is fenced and needs fresh approval.
    async fn watch_worker(self: Arc<Self>, grant: GrantBinding, exit: worker::Exit) {
        // An error means the supervisor stopped the grant worker itself.
        if let Ok(status) = exit.await {
            let id = grant.grant.as_str();
            if worker::killed_by_filter(status) {
                eprintln!(
                    "Gateway grant {id}: grant worker killed by the worker sandbox's filter (SIGSYS); grant fenced"
                );
            } else {
                eprintln!("Gateway grant {id}: grant worker ended ({status}); grant fenced");
            }
            self.fence(&grant);
        }
    }

    async fn watch_retirement(
        self: Arc<Self>,
        grant: GrantBinding,
        credential: Credential,
        expires_at_ms: u64,
        mut closed: watch::Receiver<bool>,
    ) {
        loop {
            let remain = expires_at_ms.saturating_sub(utc_ms().unwrap_or(u64::MAX));
            if remain == 0 || *closed.borrow() {
                return;
            }
            let deadline = Instant::now() + Duration::from_millis(remain.min(25_000));
            let notification = self.broker.call(
                "watch",
                &credential,
                GatewayToBroker::Watch(grant.clone()),
                deadline,
            );
            let reply = {
                let retired = closed.changed();
                tokio::pin!(retired, notification);
                match futures_util::future::select(retired, notification).await {
                    futures_util::future::Either::Left(_) => return,
                    futures_util::future::Either::Right((reply, _)) => reply,
                }
            };
            if matches!(reply,Ok(BrokerToGateway::Retire(ref retired)) if retired == &grant) {
                self.fence(&grant);
                return;
            }
            // A lost notification or dead connection grants no authority. Both
            // independently timed socket relays still require their own leases.
            let delay = if matches!(reply,Ok(BrokerToGateway::NoChange(ref live)) if live == &grant)
            {
                1
            } else {
                4
            };
            if tokio::time::timeout(Duration::from_secs(delay), closed.changed())
                .await
                .is_ok()
            {
                return;
            }
        }
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
    ingress_instance: Id,
    egress_instance: Id,
}
struct PeerTrust {
    roots: Vec<CertificateDer<'static>>,
    crls: Vec<rustls_pki_types::CertificateRevocationListDer<'static>>,
    status_until: i64,
    profile: Option<countersign_pki::Revocation>,
}
impl PeerTrust {
    fn load(rule: &Rule) -> Result<Self> {
        let (crls, status_until) = match &rule.revocation {
            Some(countersign_pki::Revocation::Crl { files }) => {
                countersign_pki::crls(files, OffsetDateTime::now_utc().unix_timestamp())?
            }
            _ => (vec![], i64::MAX),
        };
        Ok(Self {
            roots: config::anchors(&rule.roots)?,
            crls,
            status_until,
            profile: rule.revocation.clone(),
        })
    }
    fn validate(&self, host: &Origin, encoded: &[String]) -> Result<u64> {
        if encoded.is_empty() || encoded.len() > 16 {
            return Err(invalid("invalid upstream chain"));
        }
        let chain = encoded
            .iter()
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
        let mut until = self.status_until;
        if let Some(countersign_pki::Revocation::Ocsp { files, max_age_s }) = &self.profile {
            until = countersign_pki::validate_ocsp(
                &chain,
                &self.roots,
                files,
                *max_age_s,
                OffsetDateTime::now_utc().unix_timestamp(),
            )?;
        }
        for cert in chain {
            let (_, parsed) = parse_x509_certificate(&cert)
                .map_err(|_| invalid("invalid upstream certificate"))?;
            until = until.min(parsed.validity.not_after.timestamp());
        }
        Ok(u64::try_from(until)?.saturating_mul(1000))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Gateway resource limit reached")]
struct Capacity;
fn admission_status(error: &(dyn Error + Send + Sync + 'static)) -> StatusCode {
    if error.is::<tokio::time::error::Elapsed>() {
        return StatusCode::GATEWAY_TIMEOUT;
    }
    if error.is::<Capacity>() || error.is::<tokio::sync::TryAcquireError>() {
        return StatusCode::TOO_MANY_REQUESTS;
    }
    if let Some(e) = error.downcast_ref::<reqwest::Error>() {
        if e.is_timeout() {
            return StatusCode::GATEWAY_TIMEOUT;
        }
        return match e.status() {
            Some(StatusCode::UNAUTHORIZED) => StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            Some(StatusCode::TOO_MANY_REQUESTS) => StatusCode::TOO_MANY_REQUESTS,
            Some(StatusCode::GONE | StatusCode::FORBIDDEN | StatusCode::CONFLICT) => {
                StatusCode::FORBIDDEN
            }
            _ => StatusCode::SERVICE_UNAVAILABLE,
        };
    }
    StatusCode::SERVICE_UNAVAILABLE
}
fn http_response(status: StatusCode) -> ReplyBody {
    if status.is_success() {
        let builder = Response::builder().status(status);
        return builder.body(Empty::new()).expect("fixed response");
    }
    let code = match status {
        StatusCode::PROXY_AUTHENTICATION_REQUIRED => "authentication_required",
        StatusCode::FORBIDDEN => "denied",
        StatusCode::TOO_MANY_REQUESTS => "busy",
        StatusCode::GATEWAY_TIMEOUT => "timeout",
        StatusCode::SERVICE_UNAVAILABLE => "unavailable",
        StatusCode::BAD_GATEWAY => "upstream_failure",
        _ => "invalid_request",
    };
    error_response(status, code)
}
/// A refused CONNECT: no body, the error value, and the request ID the log line shares.
fn error_response(status: StatusCode, code: &str) -> ReplyBody {
    let request_id = id();
    let mut builder = Response::builder()
        .status(status)
        .header("Countersign-Error", code)
        .header("Countersign-Request-ID", request_id.as_str());
    if status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
        builder = builder.header(header::PROXY_AUTHENTICATE, "Bearer");
    }
    eprintln!("Gateway CONNECT {} {code}", request_id.as_str());
    builder.body(Empty::new()).expect("fixed response")
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
        || req.headers().get_all(header::HOST).iter().count() > 1
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
    let response = match gateway
        .broker
        .admit(&credential, &workload, &origin, deadline)
        .await
    {
        Ok(response) => response,
        Err(error) => return http_response(admission_status(error.as_ref())),
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
    let (ingress, egress) = match legs {
        Ok(legs) => legs,
        Err(error) => return http_response(admission_status(error.as_ref())),
    };
    let Ok(trust) = PeerTrust::load(rule) else {
        return http_response(StatusCode::BAD_GATEWAY);
    };
    let egress_proxy = gateway.config.egress_proxy_for(rule);
    let target = timeout_at(deadline, async {
        let denied = &gateway.config.denied_networks;
        // Never both: a proxied destination is never tried directly.
        match egress_proxy {
            Some(proxy) => egress::tunnel(proxy, &origin, denied).await,
            None => {
                let pinned = config::resolve_target(&origin, rule, denied).await?;
                Ok(TcpStream::connect(pinned).await?)
            }
        }
    })
    .await
    .map_err(Into::into)
    .and_then(|target| target);
    let target = match target {
        Ok(target) => target,
        Err(error) if egress_proxy.is_some() => {
            return error_response(StatusCode::BAD_GATEWAY, egress::error_value(error.as_ref()));
        }
        Err(_) => return http_response(StatusCode::BAD_GATEWAY),
    };
    if ingress.guard.check().is_err() || egress.guard.check().is_err() {
        return http_response(StatusCode::SERVICE_UNAVAILABLE);
    }
    let assignment = match gateway.attach(activate, &credential) {
        Ok(slot) => slot,
        Err(error) => {
            let kind = error.downcast_ref::<io::Error>().map(|e| e.kind());
            eprintln!("Gateway worker admission unavailable ({kind:?})");
            return http_response(admission_status(error.as_ref()));
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
        ingress_instance: ingress.request.instance.clone(),
        egress_instance: egress.request.instance.clone(),
    };
    tokio::spawn(async move {
        let Ok(Ok(downstream)) = timeout_at(deadline, upgraded).await else {
            return;
        };
        let guards = [ingress.guard.clone(), egress.guard.clone()];
        let mut fence = assignment.fence;
        let _connection = assignment.connection;
        let (stage, result) = tokio::select! {
            biased;
            _=fence.changed()=>("fence",Err(invalid("grant retired"))),
            r=ingress.relay(TokioIo::new(downstream),assignment.down,&connection.gateway.broker,&connection.credential,expiry)=>("ingress",r),
            r=egress.relay(target,assignment.up,&connection.gateway.broker,&connection.credential,expiry)=>("egress",r),
            r=connection.handshake(assignment.control,trust,guards.clone(),assignment.handshake,assignment.requests)=>("handshake",r),
        };
        // All selected and unselected relay futures (and their socket handles)
        // have been dropped. Observations never gate or delay socket closure.
        connection.observe(ObservationKind::IngressClosed);
        connection.observe(ObservationKind::EgressClosed);
        let lapsed = result.as_ref().is_err_and(|e| e.is::<relay::LeaseLost>())
            || guards.iter().any(|guard| guard.check().is_err());
        if lapsed {
            connection
                .gateway
                .fence(&connection.response.activation.grant);
        }
        if let Err(error) = result {
            eprintln!(
                "Gateway connection {} ended at {stage} ({:?})",
                connection.connection_id.as_str(),
                error.downcast_ref::<io::Error>().map(|e| e.kind())
            );
        }
    });
    http_response(StatusCode::OK)
}

impl Connection {
    fn observe(&self, observation: ObservationKind) {
        let Ok(permit) = self.gateway.observations.clone().try_acquire_owned() else {
            return;
        };
        let gateway = self.gateway.clone();
        let credential = self.credential.clone();
        let enforcer = if observation == ObservationKind::IngressClosed {
            &self.ingress_instance
        } else {
            &self.egress_instance
        };
        let report = Observed {
            grant: self.response.activation.grant.clone(),
            host: self.origin.clone(),
            tls_connection: self.connection_id.clone(),
            enforcer_instance: enforcer.clone(),
            observation,
        };
        tokio::spawn(async move {
            let _permit = permit;
            let _ = gateway
                .broker
                .call(
                    "observe",
                    &credential,
                    GatewayToBroker::Observed(report),
                    Instant::now() + Duration::from_secs(3),
                )
                .await;
        });
    }
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
        requests: [Arc<Semaphore>; 2],
    ) -> Result<()> {
        let grant = &self.response.activation.grant;
        let expiry = self.response.activation.expires_at_ms;
        let (evidence_deadline, peer_chain) = timeout_at(self.deadline, async {
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
            let CommandMessage::Sign {
                tls,
                scheme,
                input,
                peer_chain,
            } = worker::receive(&mut control).await?
            else {
                return Err(invalid("expected signing request"));
            };
            self.check(&guards)?;
            let cap = trust
                .validate(&self.origin, &peer_chain)?
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
            let CommandMessage::Ready = worker::receive(&mut control).await? else {
                return Err(invalid("expected upstream confirmation"));
            };
            self.check(&guards)?;
            worker::send(&mut control, &Reply::Proceed).await?;
            Ok((
                Instant::now() + Duration::from_millis(cap.saturating_sub(utc_ms()?)),
                peer_chain,
            ))
        })
        .await??;
        drop(permit);
        tokio::select! {
            result=self.refresh_peer(&peer_chain, &guards, evidence_deadline)=>result,
            result=admit_streams(control, &guards, requests, evidence_deadline, || self.observe(ObservationKind::MtlsAccepted))=>result,
        }
    }
    async fn refresh_peer(
        &self,
        chain: &[String],
        guards: &[Guard; 2],
        mut deadline: Instant,
    ) -> Result<()> {
        let rule = self
            .gateway
            .config
            .destinations
            .iter()
            .find(|r| r.id == self.response.activation.grant.scope.entry_id())
            .ok_or_else(|| invalid("missing destination rule"))?;
        loop {
            tokio::time::sleep_until(deadline.min(Instant::now() + Duration::from_secs(10))).await;
            if Instant::now() >= deadline {
                return Err(invalid("upstream evidence expired"));
            }
            guards[0].check()?;
            guards[1].check()?;
            let trust = PeerTrust::load(rule)?;
            let cap = trust
                .validate(&self.origin, chain)?
                .saturating_sub(self.gateway.config.clock_uncertainty_ms);
            for guard in guards {
                guard.cap(cap)?;
            }
            // An imported replacement may expire before the next refresh. Wake
            // even on idle sockets and preserve the earliest accepted deadline.
            let now = Instant::now();
            deadline = deadline.min(now + Duration::from_millis(cap.saturating_sub(utc_ms()?)));
        }
    }
}
async fn admit_streams(
    mut control: UnixStream,
    guards: &[Guard; 2],
    requests: [Arc<Semaphore>; 2],
    evidence_deadline: Instant,
    accepted: impl FnOnce(),
) -> Result<()> {
    let mut accepted = Some(accepted);
    let mut active = HashMap::new();
    loop {
        let message = timeout_at(evidence_deadline, worker::receive(&mut control)).await?;
        match message {
            Ok(CommandMessage::UpstreamResponse) if !active.is_empty() => {
                guards[0].check()?;
                guards[1].check()?;
                accepted
                    .take()
                    .ok_or_else(|| invalid("duplicate upstream observation"))?();
            }
            Ok(CommandMessage::OpenStream(id)) => {
                guards[0].check()?;
                guards[1].check()?;
                if active.contains_key(&id) {
                    return Err(invalid("duplicate stream ID"));
                }
                let grant = requests[0].clone().try_acquire_owned();
                let user = requests[1].clone().try_acquire_owned();
                let admitted = match (grant, user) {
                    (Ok(a), Ok(b)) => {
                        active.insert(id, (a, b));
                        true
                    }
                    _ => false,
                };
                worker::send(&mut control, &Reply::StreamGranted(admitted)).await?;
            }
            Ok(CommandMessage::CloseStream(id)) => {
                if active.remove(&id).is_none() {
                    return Err(invalid("unknown stream ID"));
                }
            }
            Err(error)
                if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|e| e.kind() == io::ErrorKind::UnexpectedEof) =>
            {
                drop(active);
                // Other guarded endpoints may still be draining the final response.
                tokio::time::sleep_until(evidence_deadline).await;
                return Ok(());
            }
            _ => return Err(invalid("invalid worker stream operation")),
        }
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

/// A grant worker's whole life: it confines itself, then serves its grant.
pub fn grant_worker() -> Result<()> {
    match countersign_gateway::worker_sandbox::confine() {
        Ok(layers) => worker::serve(layers),
        Err(error) => {
            // The startup probe passes both on: the cause as written here,
            // the layer as the exit status.
            eprintln!("{}", error.source);
            std::process::exit(worker::failed_layer_exit(error.layer));
        }
    }
}

pub async fn run(args: &[String]) -> Result<()> {
    let [verb, path] = args else {
        return Err(invalid("usage: countersign-gateway serve|env CONFIG.json"));
    };
    let config = match Config::load(Path::new(path)) {
        Ok(config) => config,
        Err(error) => {
            // In its own words, so a cause that quotes a field reads as written.
            eprintln!("{error}");
            std::process::exit(1);
        }
    };
    if verb == "env" {
        println!("{}", config.env()?);
        return Ok(());
    }
    if verb != "serve" {
        return Err(invalid("unrecognized Gateway command"));
    }
    let sandbox = config.worker_sandbox;
    let layers = match ChildHandle::verify_environment(sandbox).await {
        Ok(layers) => layers,
        Err(error) => {
            // In its own words, not as `main` would print it.
            eprintln!("{error}");
            std::process::exit(1);
        }
    };
    match sandbox.outer_layer() {
        Some(outer) => eprintln!("Gateway worker sandbox \"{sandbox}\": {outer}, {layers}"),
        None => eprintln!("Gateway worker sandbox \"{sandbox}\": {layers}"),
    }
    let policy = config.policy()?;
    // Only once the destinations it names have passed their checks.
    if let Some(proxy) = &config.egress_proxy {
        eprintln!(
            "Gateway egress proxy {proxy} {}",
            config.left_to_egress_proxy()
        );
    }
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
        observations: Arc::new(Semaphore::new(256)),
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

#[cfg(test)]
mod tests {
    use super::*;

    async fn request(control: &mut UnixStream, id: u64) -> bool {
        worker::send(control, &CommandMessage::OpenStream(id))
            .await
            .unwrap();
        match worker::receive::<Reply>(control).await.unwrap() {
            Reply::StreamGranted(granted) => granted,
            _ => panic!("unexpected stream reply"),
        }
    }

    #[tokio::test]
    async fn simultaneous_connections_share_user_and_grant_stream_limits() {
        fn connection(grant: Arc<Semaphore>, user: Arc<Semaphore>) -> UnixStream {
            let (client, server) = UnixStream::pair().unwrap();
            let now = utc_ms().unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            let guards = std::array::from_fn(|_| {
                Guard::new(
                    broker::Lease::from_reply(
                        Instant::now(),
                        now,
                        30_000u32.try_into().unwrap(),
                        now + 30_000,
                        100,
                    )
                    .unwrap(),
                )
            });
            tokio::spawn(async move {
                let _ = admit_streams(server, &guards, [grant, user], deadline, || {}).await;
            });
            client
        }
        let user = Arc::new(Semaphore::new(2));
        let grant = Arc::new(Semaphore::new(1));
        let mut a = connection(grant.clone(), user.clone());
        let mut b = connection(grant, user.clone());
        let mut c = connection(Arc::new(Semaphore::new(2)), user);
        let mut other = connection(Arc::new(Semaphore::new(1)), Arc::new(Semaphore::new(1)));
        assert!(request(&mut a, 1).await);
        assert!(!request(&mut b, 1).await); // same grant, another HTTP connection
        assert!(request(&mut c, 1).await);
        assert!(!request(&mut c, 2).await); // new grant, shared user quota
        assert!(request(&mut other, 1).await);
        worker::send(&mut a, &CommandMessage::CloseStream(1))
            .await
            .unwrap();
        // Await a new decision on a's ordered IPC channel, establishing the
        // release was processed before checking c's view of shared quota.
        assert!(request(&mut a, 2).await);
        worker::send(&mut a, &CommandMessage::CloseStream(2))
            .await
            .unwrap();
        worker::send(&mut a, &CommandMessage::Csr(String::new()))
            .await
            .unwrap();
        assert!(worker::receive::<Reply>(&mut a).await.is_err());
        assert!(request(&mut c, 3).await);
    }
}
