use crate::credentials::Credentials;
use crate::validation::{Profile, Validator};
use countersign_protocol::{ApprovalMode, DestinationEntry, DestinationPolicy, Origin, wire::Id};
use serde::Deserialize;
use std::collections::HashMap;
use std::{error::Error, fs, net::SocketAddr, num::NonZeroU32, path::PathBuf};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub origin: Origin,
    pub listen: SocketAddr,
    pub database: PathBuf,
    pub integrator: Id,
    admin_token_file: Option<PathBuf>,
    backend_token_file: PathBuf,
    gateway_token_file: Option<PathBuf>,
    workload_hmac_key_file: PathBuf,
    client_ca_file: PathBuf,
    destinations: Vec<Entry>,
    #[serde(default = "max_duration")]
    pub max_duration_s: NonZeroU32,
    #[serde(default = "audit_retention_days")]
    pub audit_retention_days: NonZeroU32,
    pub tls: Option<Tls>,
    pub web_push: Option<crate::service::PushConfig>,
}
fn audit_retention_days() -> NonZeroU32 {
    NonZeroU32::new(30).unwrap()
}
fn max_duration() -> NonZeroU32 {
    NonZeroU32::new(8 * 3600).unwrap()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    id: String,
    version: u64,
    pattern: String,
    #[serde(default)]
    whole_wildcard: bool,
    #[serde(default)]
    client_trust: Profile,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    pub certificate_path: PathBuf,
    pub key_path: PathBuf,
}
impl Config {
    pub(crate) fn credentials(&self) -> Result<Credentials, Box<dyn Error>> {
        let token = fs::read_to_string(&self.backend_token_file)?;
        let key = fs::read(&self.workload_hmac_key_file)?;
        let gateway = self
            .gateway_token_file
            .as_ref()
            .map(fs::read_to_string)
            .transpose()?;
        let admin = self
            .admin_token_file
            .as_ref()
            .map(fs::read_to_string)
            .transpose()?;
        Credentials::new(
            &key,
            token.trim_end().as_bytes(),
            gateway.as_deref().map(str::trim_end),
            admin.as_deref().map(str::trim_end),
            self.integrator.as_str().into(),
        )
        .ok_or_else(|| "invalid service credentials".into())
    }
    pub(crate) fn policy(&self) -> Result<DestinationPolicy, Box<dyn Error>> {
        let entries: Result<Vec<_>, _> = self
            .destinations
            .iter()
            .map(|e| {
                DestinationEntry::new(
                    &e.id,
                    e.version,
                    &e.pattern,
                    if e.whole_wildcard {
                        ApprovalMode::WholeWildcard
                    } else {
                        ApprovalMode::ExactHost
                    },
                )
            })
            .collect();
        Ok(DestinationPolicy::new(entries?)?)
    }
    pub(crate) fn client_validators(&self) -> Result<HashMap<String, Validator>, Box<dyn Error>> {
        self.destinations
            .iter()
            .map(|e| {
                Ok((
                    e.id.clone(),
                    Validator::new(e.client_trust.clone(), &self.client_ca_file)?,
                ))
            })
            .collect()
    }
}
