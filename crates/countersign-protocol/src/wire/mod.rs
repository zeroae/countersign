//! Typed payloads for a single text frame on an authenticated control channel.
//! Decode using the message family for the authenticated role and direction.
//! Valid structure is never proof of ownership, authorization, freshness or consent.

mod values;
pub use values::*;

use std::num::{NonZeroU32, NonZeroU64};

use serde::{Deserialize, Serialize};
use serde_json::value::{RawValue, to_raw_value};
use thiserror::Error;

use crate::{DestinationScope, Origin};

pub const SUBPROTOCOL: &str = "countersign.v1";
pub const VERSION: u16 = 1;
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const MAX_JSON_DEPTH: usize = 24;

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("frame exceeds the v1 byte limit")]
    FrameTooLarge,
    #[error("frame exceeds the v1 JSON depth limit")]
    TooDeep,
    #[error("unsupported control protocol version")]
    UnsupportedVersion,
    #[error("unexpected message for this channel and direction")]
    UnexpectedMessage,
    #[error("malformed control frame")]
    Malformed(#[source] serde_json::Error),
}
impl From<serde_json::Error> for FrameError {
    fn from(e: serde_json::Error) -> Self {
        Self::Malformed(e)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope<'a> {
    version: u16,
    request_id: Id,
    #[serde(rename = "type")]
    kind: &'a str,
    #[serde(borrow)]
    body: &'a RawValue,
}

pub struct Frame<M> {
    pub request_id: Id,
    pub message: M,
}

mod sealed {
    pub trait Sealed {}
}
pub trait Message: sealed::Sealed + Sized {
    #[doc(hidden)]
    fn parse(kind: &str, body: &RawValue) -> Result<Self, FrameError>;
    #[doc(hidden)]
    fn body(&self) -> Result<(&'static str, Box<RawValue>), FrameError>;
}

impl<M: Message> Frame<M> {
    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        check_bounds(bytes)?;
        let envelope: Envelope = serde_json::from_slice(bytes)?;
        if envelope.version != VERSION {
            return Err(FrameError::UnsupportedVersion);
        }
        // Deserialize the original body directly into its strict type. An
        // intermediate JSON Value/map would silently erase duplicate keys.
        Ok(Self {
            request_id: envelope.request_id,
            message: M::parse(envelope.kind, envelope.body)?,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let (kind, body) = self.message.body()?;
        let bytes = serde_json::to_vec(&Envelope {
            version: VERSION,
            request_id: self.request_id.clone(),
            kind,
            body: &body,
        })?;
        check_bounds(&bytes)?;
        Ok(bytes)
    }
}

// Bound recursion before serde visits any nested payload, including an
// unknown field. serde validates syntax, balanced delimiters and UTF-8.
fn check_bounds(bytes: &[u8]) -> Result<(), FrameError> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(FrameError::FrameTooLarge);
    }
    let mut depth = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    for &b in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                quoted = false;
            }
        } else {
            match b {
                b'"' => quoted = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > MAX_JSON_DEPTH {
                        return Err(FrameError::TooDeep);
                    }
                }
                b'}' | b']' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePresence {
    pub binding: DeviceBinding,
    pub connected: bool,
    pub connected_at_ms: u64,
    pub observed_address: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Devices {
    pub devices: Vec<DevicePresence>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ForgetDevices {
    pub targets: Vec<DeviceBinding>,
    pub all_others: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityEvent {
    pub id: Id,
    pub kind: String,
    pub actor: Option<DeviceBinding>,
    pub targets: Vec<DeviceBinding>,
    pub occurred_at_ms: u64,
    pub observed_address: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkloadBinding {
    pub integrator: Id,
    pub user: Id,
    pub context: Id,
    pub workload: Id,
    pub workload_generation: NonZeroU64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceBinding {
    pub pairing: Id,
    pub key: Id,
    pub channel_generation: NonZeroU64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GrantBinding {
    pub workload: WorkloadBinding,
    pub grant: Id,
    pub grant_version: NonZeroU64,
    pub worker: Id,
    pub worker_generation: NonZeroU64,
    pub scope: DestinationScope,
    pub device: DeviceBinding,
    pub cert_sha256: Fingerprint,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Notice {
    pub id: Id,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Empty {}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Inbox {
    pub ids: Vec<Id>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PairingPending {
    pub attempt: Id,
    pub code: Id,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayActivation {
    pub activation: Activate,
    pub chain: PublicChain,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Enroll {
    /// Uncompressed SEC1 P-256 public point. The enrollment verifier checks curve membership.
    pub public_sec1: FixedBytes<65>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Authenticate {
    pub pairing: Id,
    pub key: Id,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ProofPurpose {
    Pair { attempt: Id },
    Reconnect { pairing: Id },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub purpose: ProofPurpose,
    pub integrator_origin: Origin,
    pub broker_origin: Origin,
    pub user: Id,
    pub key: Id,
    pub connection: Id,
    pub nonce: FixedBytes<32>,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceProof {
    pub connection: Id,
    /// Compact ES256 JWS. The Broker verifies the protected header,
    /// challenge, audience, signature and one-use binding before authentication.
    pub compact_jws: CompactJws,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OfferBinding {
    pub approval: Id,
    pub approval_version: NonZeroU64,
    pub offer: Id,
    pub device: DeviceBinding,
}

/// Public issuer distinguished names are DER-encoded X.509 Name values.
pub type DistinguishedName = Bytes<16384>;

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct IdentityHints {
    pub issuer_names: Vec<DistinguishedName>,
    /// None allows any eligible leaf. Some(empty) represents an account with no enrolled leaf.
    pub cert_fingerprints: Option<Vec<Fingerprint>>,
    pub signature_schemes: Vec<SignatureScheme>,
}

impl IdentityHints {
    fn is_empty(&self) -> bool {
        self.issuer_names.is_empty()
            && self.cert_fingerprints.is_none()
            && self.signature_schemes.is_empty()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Offer {
    #[serde(default, skip_serializing_if = "IdentityHints::is_empty")]
    pub identity_hints: IdentityHints,
    pub binding: OfferBinding,
    pub workload: WorkloadBinding,
    pub initiating_host: Origin,
    pub scope: DestinationScope,
    pub default_duration_s: NonZeroU32,
    pub max_duration_s: NonZeroU32,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Answer {
    Approve {
        duration_s: NonZeroU32,
        chain: PublicChain,
        cert_sha256: Fingerprint,
    },
    Deny,
    Cancel,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Decide {
    pub binding: OfferBinding,
    pub answer: Answer,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Activate {
    pub grant: GrantBinding,
    pub approval: Id,
    pub offer: Id,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Connect {
    pub workload: WorkloadBinding,
    pub host: Origin,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Enforcer {
    Ingress,
    Egress,
    SigningRelay,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LeaseRequest {
    pub grant: GrantBinding,
    pub enforcer: Enforcer,
    pub instance: Id,
    pub generation: NonZeroU64,
    pub sequence: NonZeroU64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum LeaseDisposition {
    Granted {
        budget_ms: NonZeroU32,
        valid_until_ms: u64,
    },
    Refused,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseReply {
    pub binding: LeaseRequest,
    pub disposition: LeaseDisposition,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub grant: GrantBinding,
    pub host: Origin,
    pub tls_connection: Id,
    pub operation: Id,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureScheme {
    EcdsaNistp256Sha256,
    EcdsaNistp384Sha384,
    RsaPssSha256,
    RsaPssSha384,
    RsaPssSha512,
    RsaPkcs1Sha256,
    RsaPkcs1Sha384,
    RsaPkcs1Sha512,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Sign {
    pub binding: Operation,
    pub tls: TlsVersion,
    pub scheme: SignatureScheme,
    pub certificate_verify: SigningInput,
    pub deadline_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Signed {
    pub binding: Operation,
    pub signature: SignatureBytes,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Unauthenticated,
    Unavailable,
    Denied,
    Expired,
    AlreadyResolved,
    InvalidRequest,
    Busy,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rejection {
    pub code: ErrorCode,
}

macro_rules! messages {
    ($family:ident { $($variant:ident ($data:ty) => $name:literal),+ $(,)? }) => {
        #[derive(Clone, Debug)]
        pub enum $family { $( $variant($data), )+ }
        impl sealed::Sealed for $family {}
        impl Message for $family {
            fn parse(kind: &str, body: &RawValue) -> Result<Self, FrameError> {
                match kind {
                    $($name => Ok(Self::$variant(serde_json::from_str(body.get())?)),)+
                    _ => Err(FrameError::UnexpectedMessage),
                }
            }

            fn body(&self) -> Result<(&'static str, Box<RawValue>), FrameError> {
                match self { $( Self::$variant(value) => Ok(($name, to_raw_value(value)?)), )+ }
            }
        }
    }
}

messages!(CompanionToBroker {
    RevokeApproval(Notice) => "revoke_approval",
    Devices(Empty) => "devices",
    ForgetDevices(ForgetDevices) => "forget_devices",
    Enroll(Enroll) => "enroll",
    Authenticate(Authenticate) => "authenticate",
    Proof(DeviceProof) => "proof",
    Fetch(Notice) => "fetch",
    Inbox(Empty) => "inbox",
    Decide(Decide) => "decide",
    Activated(Activate) => "activated",
    Signed(Signed) => "signed",
    Cancel(Operation) => "cancel",
    Error(Rejection) => "error",
});

messages!(BrokerToCompanion {
    RevokeRecorded(Notice) => "revoke_recorded",
    Devices(Devices) => "devices",
    SecurityEvent(SecurityEvent) => "security_event",
    PairingPending(PairingPending) => "pairing_pending",
    Inbox(Inbox) => "inbox",
    Challenge(Challenge) => "challenge",
    Authenticated(DeviceBinding) => "authenticated",
    Notify(Notice) => "notify",
    Offer(Offer) => "offer",
    Activate(Activate) => "activate",
    Retire(GrantBinding) => "retire",
    Sign(Sign) => "sign",
    Cancel(Operation) => "cancel",
    Error(Rejection) => "error",
});

/// A trusted Gateway's observation of one exact socket. Recording it grants
/// no authority to continue carrying traffic or performing a signature.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ObservationKind {
    MtlsAccepted,
    IngressClosed,
    EgressClosed,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Observed {
    pub grant: GrantBinding,
    pub host: Origin,
    pub tls_connection: Id,
    pub enforcer_instance: Id,
    pub observation: ObservationKind,
}

messages!(GatewayToBroker {
    Watch(GrantBinding) => "watch",
    Observed(Observed) => "observed",
    Connect(Connect) => "connect",
    Lookup(Connect) => "lookup",
    RenewLease(LeaseRequest) => "renew_lease",
    Sign(Sign) => "sign",
    Cancel(Operation) => "cancel",
});

messages!(BrokerToGateway {
    NoChange(GrantBinding) => "no_change",
    Observed(Observed) => "observed",
    Pending(Notice) => "pending",
    Activate(GatewayActivation) => "activate",
    Retire(GrantBinding) => "retire",
    Lease(LeaseReply) => "lease",
    Signed(Signed) => "signed",
    Cancel(Operation) => "cancel",
    Error(Rejection) => "error",
});
