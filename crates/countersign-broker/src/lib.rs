//! Durable Broker approval arbitration. Callers run inside the trusted Broker.
//! Account, Workload and pairing arguments come from authenticated bindings.
//! An approved record captures consent. Authorizing a signature or traffic also
//! requires live policy, certificate validation, session and lease checks.

use countersign_protocol::{DestinationPolicy, Origin};
use serde::Serialize;
use std::num::NonZeroU32;
use thiserror::Error;
use uuid::Uuid;

mod sqlite;
pub use sqlite::SqliteApprovalStore;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("request is unavailable in this authenticated scope")]
    Unavailable,
    #[error("invalid authority input")]
    InvalidInput,
    #[error("decision ID reused with different content")]
    DecisionConflict,
    #[error("approval is no longer pending")]
    Resolved,
    #[error("approval capacity reached")]
    Capacity,
    #[error("database operation failed")]
    Database(#[from] rusqlite::Error),
}

pub type Result<T> = std::result::Result<T, StoreError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owner {
    pub integrator: String,
    pub user: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workload {
    pub owner: Owner,
    pub context: String,
    pub instance: String,
    pub generation: u64,
}

/// Issued only after the caller verifies pairing-key possession. Every successful
/// reconnect fences the previous generation, including outstanding offers.
#[derive(Debug, Clone)]
pub struct DeviceSession {
    owner: Owner,
    pairing: String,
    key: String,
    generation: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trigger {
    Traffic,
    ExplicitConnect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalState {
    Pending,
    Approved,
    Denied,
    Cancelled,
    Expired,
    Replaced,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    pub id: Uuid,
    pub workload: Workload,
    pub entry_id: String,
    pub entry_version: u64,
    pub scope: String,
    pub initiating_origin: String,
    pub max_duration_seconds: NonZeroU32,
    pub pending_until: i64,
    pub state: ApprovalState,
}

#[derive(Debug, Clone)]
pub struct Offer {
    pub id: Uuid,
    pub approval: Approval,
}

/// The trusted certificate validator supplies the SHA-256 digest and expiry.
/// These fields must never be copied from an unvalidated device decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidatedCertificate {
    pub sha256: [u8; 32],
    /// The earliest not-after across the selected chain, which caps the grant.
    pub not_after_unix_seconds: i64,
    /// The selected leaf's own subject, issuer and not-after, which the
    /// approval status call reports.
    pub subject: String,
    pub issuer: String,
    pub leaf_not_after_unix_seconds: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Decision {
    Approve {
        certificate: ValidatedCertificate,
        duration_seconds: NonZeroU32,
    },
    Deny,
    Cancel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    Committed,
    AlreadyResolved,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedGrant {
    pub id: Uuid,
    pub approval_id: Uuid,
    pub pairing: String,
    pub pairing_key: String,
    pub certificate_sha256: [u8; 32],
    pub expires_at: i64,
}

pub trait ApprovalStore {
    fn request(
        &mut self,
        workload: &Workload,
        policy: &DestinationPolicy,
        origin: &Origin,
        max_duration_seconds: NonZeroU32,
        trigger: Trigger,
    ) -> Result<Approval>;

    /// Stage a separate pending decision. Only a successfully committed
    /// replacement can interrupt the predecessor's original access window.
    fn renew(
        &mut self,
        workload: &Workload,
        policy: &DestinationPolicy,
        previous: Uuid,
        max_duration_seconds: NonZeroU32,
    ) -> Result<Approval>;

    fn authenticate_device(
        &mut self,
        owner: &Owner,
        pairing: &str,
        key: &str,
    ) -> Result<DeviceSession>;

    fn offer(&mut self, device: &DeviceSession, approval: Uuid) -> Result<Offer>;

    fn decide(
        &mut self,
        device: &DeviceSession,
        offer: Uuid,
        decision_id: Uuid,
        decision: &Decision,
    ) -> Result<Disposition>;

    /// Withdraw a scoped request and its pending renewal as one operation.
    /// When called by a device, only its winning pairing and key can revoke.
    fn revoke(
        &mut self,
        owner: &Owner,
        device: Option<&DeviceSession>,
        id: Uuid,
    ) -> Result<Vec<Uuid>>;

    /// Authenticate current membership and optional destination permission for
    /// a previously verified Workload credential.
    fn permit(&self, workload: &Workload, entry: Option<&str>) -> Result<()>;

    /// Consume the next monotonic renewal of a live enforcer. The caller has
    /// capped the deadline by the token, grant and verified certificate status.
    fn issue_lease(
        &mut self,
        request: &countersign_protocol::wire::LeaseRequest,
        gateway_boot: Uuid,
        current_device: &countersign_protocol::wire::DeviceBinding,
        at_ms: u64,
        until_ms: u64,
    ) -> Result<()>;

    /// Bind the worker and validated public identity exactly once. The
    /// reference store erases its working copy when the grant ends.
    fn bind_activation(
        &mut self,
        workload: &Workload,
        activation: &countersign_protocol::wire::Activate,
        chain: &countersign_protocol::wire::PublicChain,
        verified_at_ms: u64,
        valid_until_ms: u64,
    ) -> Result<()>;

    /// Return consent for the exact Workload binding. This is an observation of
    /// the committed decision, not an active grant lease.
    fn approved_grant(
        &self,
        workload: &Workload,
        approval_id: Uuid,
    ) -> Result<Option<ApprovedGrant>>;
}

pub mod config;
mod credentials;
pub mod service;

mod validation;
