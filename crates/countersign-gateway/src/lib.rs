//! Interception certificates used on the Workload-facing TLS connection.

mod sidecar;

pub use sidecar::{IssueError, SidecarIssuer};

pub mod upstream;

mod shared_issuer;
pub use shared_issuer::{SharedCaSource, SharedIssuer};
