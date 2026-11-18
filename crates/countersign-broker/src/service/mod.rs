//! Single-process reference Broker. Independent instances need a shared live
//! channel registry in addition to the durable approval store.
use super::{
    ApprovalStore, DeviceSession, Owner, SqliteApprovalStore, Workload, config::Config,
    credentials::Credentials,
};
use crate::validation::{Invalid, Validator};
use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use countersign_protocol::{DestinationPolicy, Origin, wire as w};
use rusqlite::{OptionalExtension, params};
use std::{
    collections::HashMap,
    error::Error,
    num::{NonZeroU32, NonZeroU64},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Semaphore, mpsc, oneshot};
use uuid::Uuid;

mod backend;
mod maintenance;
mod observations;
mod push;
pub use push::PushConfig;
mod companion;
mod controls;
mod gateway;

type Result<T> = std::result::Result<T, Fault>;
#[derive(Debug)]
enum Fault {
    Unavailable,
    Invalid,
    Unauthenticated,
    Expired,
    Busy,
    Denied,
    Resolved,
    Storage,
}
impl From<rusqlite::Error> for Fault {
    fn from(_: rusqlite::Error) -> Self {
        Self::Storage
    }
}
impl From<super::StoreError> for Fault {
    fn from(e: super::StoreError) -> Self {
        match e {
            super::StoreError::Capacity => Self::Busy,
            super::StoreError::Database(_) => Self::Storage,
            super::StoreError::InvalidInput | super::StoreError::DecisionConflict => Self::Invalid,
            super::StoreError::Unavailable => Self::Unavailable,
            super::StoreError::Resolved => Self::Resolved,
        }
    }
}
impl IntoResponse for Fault {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::Unavailable => (StatusCode::NOT_FOUND, "unavailable"),
            Self::Invalid => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::Unauthenticated => (StatusCode::UNAUTHORIZED, "unauthenticated"),
            Self::Expired => (StatusCode::GONE, "expired"),
            Self::Busy => (StatusCode::TOO_MANY_REQUESTS, "busy"),
            Self::Denied => (StatusCode::FORBIDDEN, "denied"),
            Self::Resolved => (StatusCode::CONFLICT, "already_resolved"),
            Self::Storage => (StatusCode::SERVICE_UNAVAILABLE, "authority_unavailable"),
        };
        (status, code).into_response()
    }
}

#[derive(Clone)]
pub struct Service {
    push_sender: Option<Arc<push::Sender>>,
    state: Arc<Mutex<Authority>>,
    credentials: Arc<Credentials>,
    watchers: Arc<Semaphore>,
    slots: Arc<Semaphore>,
    connections: Arc<Semaphore>,
}
struct PendingPair {
    code: String,
    until: u64,
    user: oneshot::Sender<w::Id>,
}
struct Peer {
    session: DeviceSession,
    binding: w::DeviceBinding,
    send: mpsc::Sender<w::Frame<w::BrokerToCompanion>>,
}
struct LiveGrant {
    retire_signal: tokio::sync::watch::Sender<()>,
    gateway_boot: Option<Uuid>,
    activation: w::Activate,
    chain: w::PublicChain,
    acknowledged: bool,
    operations: std::collections::HashSet<w::Id>,
}
struct SignWait {
    leased_until: tokio::time::Instant,
    request_id: w::Id,
    scheme: w::SignatureScheme,
    input: w::SigningInput,
    op: w::Operation,
    deadline: u64,
    reply: oneshot::Sender<w::Signed>,
}
struct Authority {
    _database_lock: std::fs::File,
    audit_retention_days: NonZeroU32,
    store: SqliteApprovalStore,
    origin: Origin,
    integrator: w::Id,
    policy: DestinationPolicy,
    max_duration: NonZeroU32,
    validators: HashMap<String, Validator>,
    announced: HashMap<Uuid, u64>,
    enrollments: HashMap<String, PendingPair>,
    peers: HashMap<String, Peer>,
    grants: HashMap<String, LiveGrant>,
    waiting: HashMap<(w::Id, w::Id), SignWait>,
}
impl Service {
    pub fn open(config: &Config) -> std::result::Result<Self, Box<dyn Error>> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let credentials = Arc::new(config.credentials()?);
        let policy = config.policy()?;
        let validators = config.client_validators()?;
        let push_sender = config.web_push.as_ref().map(PushConfig::load).transpose()?;
        let lock = maintenance::lock_database(&config.database)?;
        let mut store = SqliteApprovalStore::open(&config.database)?;
        maintenance::fence_boot(
            &mut store,
            config.integrator.as_str(),
            &config.origin,
            false,
        )
        .map_err(|_| "could not fence prior authority")?;
        let state = Authority {
            _database_lock: lock,
            audit_retention_days: config.audit_retention_days,
            store,
            origin: config.origin.clone(),
            integrator: config.integrator.clone(),
            policy,
            max_duration: config.max_duration_s,
            validators,
            announced: HashMap::new(),
            enrollments: HashMap::new(),
            peers: HashMap::new(),
            grants: HashMap::new(),
            waiting: HashMap::new(),
        };
        Ok(Self {
            push_sender,
            state: Arc::new(Mutex::new(state)),
            credentials,
            watchers: Arc::new(Semaphore::new(512)),
            slots: Arc::new(Semaphore::new(128)),
            connections: Arc::new(Semaphore::new(256)),
        })
    }
    /// Run with the service stopped, after restoring a database backup. A fresh
    /// enrollment is required for every device. The administrator reconciles
    /// access policy and clears emergency stop before allowing traffic.
    pub fn recover_backup(config: &Config) -> std::result::Result<(), Box<dyn Error>> {
        let _lock = maintenance::lock_database(&config.database)?;
        let mut store = SqliteApprovalStore::open(&config.database)?;
        maintenance::fence_boot(&mut store, config.integrator.as_str(), &config.origin, true)
            .map_err(|_| "backup recovery failed".into())
    }

    async fn apply<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Authority) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let permit = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Fault::Busy)?;
        let state = self.state.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut a = state.lock().map_err(|_| Fault::Storage)?;
            f(&mut a)
        })
        .await
        .map_err(|_| Fault::Storage)?
    }
    pub fn router(self) -> Router {
        maintenance::start(&self.state);
        if let Some(sender) = self.push_sender.clone() {
            push::start(self.clone(), sender);
        }
        Router::new()
            .merge(push::routes())
            .route("/v1/companion", get(companion::upgrade))
            .route("/v1/gateway/{operation}", post(gateway::request))
            .route("/v1/backend/workloads", post(backend::workload))
            .route(
                "/v1/backend/workloads/retire",
                post(controls::retire_workload),
            )
            .route("/v1/backend/pairings/confirm", post(backend::confirm))
            .route("/v1/backend/requests", post(backend::request))
            .route("/v1/backend/status", post(backend::status))
            .route("/v1/backend/revoke", post(backend::revoke))
            .route("/v1/backend/renew", post(backend::renew))
            .route("/v1/backend/contexts/close", post(controls::close_context))
            .route("/v1/admin/control", post(controls::admin))
            .route("/v1/backend/devices", post(controls::list_devices))
            .route("/v1/backend/pairings/forget", post(controls::forget_api))
            .layer(DefaultBodyLimit::max(w::MAX_FRAME_BYTES))
            .with_state(self)
    }
}
fn clock_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .ok_or(Fault::Storage)
}
fn fresh() -> w::Id {
    w::Id::new(Uuid::new_v4().to_string()).expect("UUID is an opaque ID")
}
fn uid(id: &w::Id) -> Result<Uuid> {
    Uuid::parse_str(id.as_str()).map_err(|_| Fault::Invalid)
}
fn wire_id(id: Uuid) -> w::Id {
    w::Id::new(id.to_string()).expect("valid UUID")
}
fn binding(v: &w::WorkloadBinding) -> Workload {
    Workload {
        owner: Owner {
            integrator: v.integrator.as_str().into(),
            user: v.user.as_str().into(),
        },
        context: v.context.as_str().into(),
        instance: v.workload.as_str().into(),
        generation: v.workload_generation.get(),
    }
}
fn workload(v: &Workload) -> Result<w::WorkloadBinding> {
    let id = |s: &str| w::Id::new(s.to_owned()).map_err(|_| Fault::Invalid);
    Ok(w::WorkloadBinding {
        integrator: id(&v.owner.integrator)?,
        user: id(&v.owner.user)?,
        context: id(&v.context)?,
        workload: id(&v.instance)?,
        workload_generation: NonZeroU64::new(v.generation).ok_or(Fault::Invalid)?,
    })
}
fn operation_key(op: &w::Operation) -> (w::Id, w::Id) {
    (op.grant.grant.clone(), op.operation.clone())
}
fn send(peer: &Peer, id: w::Id, message: w::BrokerToCompanion) -> Result<()> {
    peer.send
        .try_send(w::Frame {
            request_id: id,
            message,
        })
        .map_err(|_| Fault::Busy)
}
impl Authority {
    fn live_workload(&self, b: &w::WorkloadBinding) -> Result<()> {
        self.permit(b, None)
    }
    fn allow_destination(&self, b: &w::WorkloadBinding, entry: &str) -> Result<()> {
        self.permit(b, Some(entry))
    }
    fn permit(&self, b: &w::WorkloadBinding, entry: Option<&str>) -> Result<()> {
        if b.integrator != self.integrator {
            return Err(Fault::Denied);
        }
        self.store.permit(&binding(b), entry).map_err(|e| match e {
            crate::StoreError::Unavailable => Fault::Denied,
            other => other.into(),
        })
    }
    fn notify_pending(&mut self, r: &crate::Approval) {
        if self
            .announced
            .insert(r.id, r.pending_until as u64 * 1000)
            .is_none()
        {
            self.notify(&r.workload.owner.user, wire_id(r.id));
        }
    }
    fn notify(&self, user: &str, id: w::Id) {
        for peer in self.peers.values().filter(|p| p.session.owner.user == user) {
            let _ = send(
                peer,
                fresh(),
                w::BrokerToCompanion::Notify(w::Notice { id: id.clone() }),
            );
        }
    }
    fn require_gateway(&self, b: &w::GrantBinding, boot: Uuid) -> Result<()> {
        if self
            .grants
            .get(b.grant.as_str())
            .and_then(|g| g.gateway_boot)
            == Some(boot)
        {
            Ok(())
        } else {
            Err(Fault::Denied)
        }
    }
    fn validate_grant(&mut self, b: &w::GrantBinding, at: u64) -> Result<u64> {
        let limit = self.validate_traffic(b, at)?;
        let g = self
            .grants
            .get(b.grant.as_str())
            .ok_or(Fault::Unavailable)?;
        if g.activation.grant.device != b.device || !g.acknowledged {
            return Err(Fault::Unavailable);
        }
        Ok(limit)
    }
    fn validate_traffic(&mut self, b: &w::GrantBinding, at: u64) -> Result<u64> {
        self.allow_destination(&b.workload, b.scope.entry_id())?;
        let g = self
            .grants
            .get(b.grant.as_str())
            .ok_or(Fault::Unavailable)?;
        let mut expected = g.activation.grant.clone();
        expected.device.channel_generation = b.device.channel_generation;
        if expected != *b
            || b.device.channel_generation > g.activation.grant.device.channel_generation
        {
            return Err(Fault::Unavailable);
        }
        if g.activation.expires_at_ms <= at {
            return Err(Fault::Expired);
        }
        let stored = self
            .store
            .approved_grant(&binding(&b.workload), uid(&g.activation.approval)?)?
            .ok_or(Fault::Denied)?;
        if stored.id != uid(&b.grant)? {
            return Err(Fault::Denied);
        }
        let verifier = self
            .validators
            .get(b.scope.entry_id())
            .ok_or(Fault::Denied)?;
        match verifier.verify(b.workload.user.as_str(), &g.chain, at) {
            Ok(valid) => Ok(g
                .activation
                .expires_at_ms
                .min((valid.evidence_end as u64).saturating_mul(1000))),
            Err(Invalid::Revoked) => {
                controls::certificate_revoked(self, b)?;
                Err(Fault::Denied)
            }
            Err(Invalid::Evidence) => Err(Fault::Unavailable),
        }
    }
    fn prune(&mut self, at: u64) {
        self.announced.retain(|_, until| *until > at);
        self.enrollments.retain(|_, v| v.until > at);
        self.waiting
            .retain(|_, v| v.deadline > at && !v.reply.is_closed());
        self.grants.retain(|_, v| v.activation.expires_at_ms > at);
    }
}
