//! Interception certificates used on the Workload-facing TLS connection.

mod sidecar;

pub use sidecar::{IssueError, SidecarIssuer};

pub mod upstream;

mod shared_issuer;
pub use shared_issuer::{SharedCaSource, SharedIssuer};

/// The worker sandbox's base layers, which every grant worker applies to itself.
#[cfg(target_os = "linux")]
pub mod worker_sandbox;
