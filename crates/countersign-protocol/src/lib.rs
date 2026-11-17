//! Shared types for the Countersign Broker, Gateway and Companion.

mod destination;

pub use destination::{
    ApprovalMode, DestinationEntry, DestinationPattern, DestinationPolicy, DestinationScope,
    Origin, PolicyError,
};

pub mod wire;
