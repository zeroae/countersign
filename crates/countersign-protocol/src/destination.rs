use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("expected an HTTPS DNS authority")]
    InvalidHost,
    #[error("expected a decimal port from 1 to 65535")]
    InvalidPort,
    #[error("CONNECT requires an explicit port")]
    MissingPort,
    #[error("a destination entry needs a nonempty ID and a positive version")]
    InvalidEntry,
    #[error("duplicate destination entry ID")]
    DuplicateId,
    #[error("duplicate canonical destination pattern")]
    DuplicatePattern,
    #[error("whole-wildcard approval requires a wildcard destination")]
    InvalidApprovalMode,
}

/// A concrete HTTPS origin, represented on the wire as an A-label name and port.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Origin {
    host: String,
    port: u16,
}

impl Origin {
    /// An omitted HTTPS port becomes 443. Use `parse_connect` on CONNECT targets.
    pub fn parse(authority: &str) -> Result<Self, PolicyError> {
        let (host, port) = match authority.split_once(':') {
            Some((host, text)) => {
                if text.starts_with('0') || !text.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(PolicyError::InvalidPort);
                }
                let port = text.parse::<u16>().map_err(|_| PolicyError::InvalidPort)?;
                (host, port)
            }
            None => (authority, 443),
        };

        // Strip one optional DNS root dot. IDNA's strict profile checks STD3,
        // A-label validity, label/total length, and empty/interior root labels.
        let host = host.strip_suffix('.').unwrap_or(host);
        let host = idna::domain_to_ascii_strict(host).map_err(|_| PolicyError::InvalidHost)?;

        // URL stacks can interpret decimal, octal, hex and shortened IPv4 syntax
        // differently from system resolvers. Deny numeric-ending domains before DNS.
        let last = host.rsplit('.').next().unwrap_or_default();
        let numeric = last.bytes().all(|b| b.is_ascii_digit());
        let hex = last
            .strip_prefix("0x")
            .is_some_and(|n| n.bytes().all(|b| b.is_ascii_hexdigit()));
        if numeric || hex {
            return Err(PolicyError::InvalidHost);
        }
        Ok(Self { host, port })
    }

    pub fn parse_connect(authority: &str) -> Result<Self, PolicyError> {
        if !authority.contains(':') {
            return Err(PolicyError::MissingPort);
        }
        Self::parse(authority)
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl FromStr for Origin {
    type Err = PolicyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

impl Serialize for Origin {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Origin {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum DestinationPattern {
    Exact(Origin),
    /// Origin holds the suffix and port. Matches exactly one additional DNS label.
    Wildcard(Origin),
}

impl DestinationPattern {
    pub fn parse(pattern: &str) -> Result<Self, PolicyError> {
        match pattern.strip_prefix("*.") {
            Some(suffix) => Origin::parse(suffix).map(Self::Wildcard),
            None => Origin::parse(pattern).map(Self::Exact),
        }
    }

    fn bare_origin(&self) -> &Origin {
        match self {
            Self::Exact(origin) | Self::Wildcard(origin) => origin,
        }
    }

    pub fn matches(&self, target: &Origin) -> bool {
        match self {
            Self::Exact(exact) => exact == target,
            Self::Wildcard(suffix) => {
                suffix.port() == target.port()
                    && target
                        .host()
                        .split_once('.')
                        .is_some_and(|(_, rest)| rest == suffix.host())
            }
        }
    }
}

impl fmt::Display for DestinationPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(origin) => write!(f, "{origin}"),
            Self::Wildcard(suffix) => write!(f, "*.{suffix}"),
        }
    }
}

impl Serialize for DestinationPattern {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for DestinationPattern {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::parse(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    #[default]
    ExactHost,
    WholeWildcard,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DestinationEntry {
    id: String,
    version: u64,
    pattern: DestinationPattern,
    approval: ApprovalMode,
}

impl DestinationEntry {
    pub fn new(
        id: impl Into<String>,
        version: u64,
        pattern: &str,
        approval: ApprovalMode,
    ) -> Result<Self, PolicyError> {
        let id = id.into();
        if id.trim().is_empty() || id.chars().any(char::is_control) || version == 0 {
            return Err(PolicyError::InvalidEntry);
        }
        let pattern = DestinationPattern::parse(pattern)?;
        if approval == ApprovalMode::WholeWildcard
            && matches!(pattern, DestinationPattern::Exact(_))
        {
            return Err(PolicyError::InvalidApprovalMode);
        }
        Ok(Self {
            id,
            version,
            pattern,
            approval,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn pattern(&self) -> &DestinationPattern {
        &self.pattern
    }

    pub fn approval_mode(&self) -> ApprovalMode {
        self.approval
    }

    /// RFC 5280 DNS subtree for the sidecar CA. The Gateway still enforces the exact pattern and port.
    pub fn constraint_dns_name(&self) -> &str {
        self.pattern.bare_origin().host()
    }
}

/// Destination portion of an approval or grant. The Broker separately binds the
/// authenticated owner, workload, certificate and lifetime.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationScope {
    entry_id: String,
    entry_version: u64,
    pattern: DestinationPattern,
}

impl DestinationScope {
    pub fn entry_id(&self) -> &str {
        &self.entry_id
    }

    pub fn entry_version(&self) -> u64 {
        self.entry_version
    }

    pub fn pattern(&self) -> &DestinationPattern {
        &self.pattern
    }
}

#[derive(Clone, Debug, Default)]
pub struct DestinationPolicy {
    entries: Vec<DestinationEntry>,
}

impl DestinationPolicy {
    pub fn new(entries: Vec<DestinationEntry>) -> Result<Self, PolicyError> {
        let mut ids = HashSet::new();
        let mut patterns = HashSet::new();
        for entry in &entries {
            if !ids.insert(&entry.id) {
                return Err(PolicyError::DuplicateId);
            }
            if !patterns.insert(&entry.pattern) {
                return Err(PolicyError::DuplicatePattern);
            }
        }
        Ok(Self { entries })
    }

    pub fn entries(&self) -> &[DestinationEntry] {
        &self.entries
    }

    pub fn resolve(&self, origin: &Origin) -> Option<&DestinationEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.pattern.matches(origin))
            .max_by_key(|entry| matches!(entry.pattern, DestinationPattern::Exact(_)))
    }

    pub fn scope_for(&self, origin: &Origin) -> Option<DestinationScope> {
        let entry = self.resolve(origin)?;
        let pattern = match entry.approval {
            ApprovalMode::ExactHost => DestinationPattern::Exact(origin.clone()),
            ApprovalMode::WholeWildcard => entry.pattern.clone(),
        };
        Some(DestinationScope {
            entry_id: entry.id.clone(),
            entry_version: entry.version,
            pattern,
        })
    }

    /// Re-resolve the current winning rule. A wildcard grant never overrides a
    /// more specific entry, even if that entry appeared after grant creation.
    pub fn covers(&self, grant: &DestinationScope, target: &Origin) -> bool {
        self.scope_for(target).as_ref() == Some(grant)
    }
}
