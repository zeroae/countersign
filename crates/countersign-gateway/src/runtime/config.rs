use std::collections::HashSet;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use countersign_protocol::{
    ApprovalMode, DestinationEntry, DestinationPolicy, Origin, wire::WorkloadBinding,
};
use ipnet::IpNet;
use rustls_pki_types::{CertificateDer, CertificateRevocationListDer, pem::PemObject};
use serde::Deserialize;

use super::{Result, invalid};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub listen: SocketAddr,
    pub proxy_url: String,
    pub ca_output: PathBuf,
    pub broker_url: String,
    pub broker_ca: PathBuf,
    pub workload_token: Option<PathBuf>,
    pub workload: Option<WorkloadBinding>,
    pub destinations: Vec<Rule>,
    #[serde(default)]
    pub denied_networks: Vec<IpNet>,
    pub shared: Option<Shared>,
    /// Conservative upper bound on the difference between Broker and Gateway
    /// UTC. The operator must maintain synchronized clocks.
    #[serde(default = "default_uncertainty")]
    pub clock_uncertainty_ms: u64,
}

fn default_uncertainty() -> u64 {
    1000
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Shared {
    pub listener_cert: PathBuf,
    pub listener_key: PathBuf,
    pub gateway_token: PathBuf,
    pub ca: countersign_gateway::SharedCaSource,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Rule {
    pub id: String,
    pub version: u64,
    pub pattern: String,
    #[serde(default)]
    pub approval: ApprovalMode,
    #[serde(default)]
    pub private_networks: Vec<IpNet>,
    pub roots: PathBuf,
    #[serde(default)]
    pub crls: Vec<PathBuf>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let config: Self = serde_json::from_slice(&fs::read(path)?)?;
        if config.shared.is_none() != (config.workload.is_some() && config.workload_token.is_some())
            || config.clock_uncertainty_ms >= 30000
        {
            return Err(invalid("invalid Gateway credential or clock configuration"));
        }
        for url in [&config.broker_url, &config.proxy_url] {
            let parsed = reqwest::Url::parse(url)?;
            if parsed.host_str().is_none()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.query().is_some()
                || parsed.fragment().is_some()
                || parsed.path() != "/"
            {
                return Err(invalid("expected a URL origin"));
            }
        }
        if reqwest::Url::parse(&config.broker_url)?.scheme() != "https"
            || reqwest::Url::parse(&config.proxy_url)?.scheme()
                != if config.shared.is_some() {
                    "https"
                } else {
                    "http"
                }
        {
            return Err(invalid("invalid Gateway URL scheme"));
        }
        Ok(config)
    }

    pub fn policy(&self) -> Result<DestinationPolicy> {
        let entries = self
            .destinations
            .iter()
            .map(|rule| DestinationEntry::new(&rule.id, rule.version, &rule.pattern, rule.approval))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(DestinationPolicy::new(entries)?)
    }
    pub fn env(&self) -> Result<String> {
        fn quote(value: &str) -> String {
            format!("'{}'", value.replace('\'', "'\\''"))
        }
        let path = self
            .ca_output
            .to_str()
            .ok_or_else(|| invalid("CA path is not Unicode"))?;
        Ok(format!(
            "export HTTPS_PROXY={}\nexport SSL_CERT_FILE={}\nexport REQUESTS_CA_BUNDLE={}\nexport NODE_EXTRA_CA_CERTS={}",
            quote(&self.proxy_url),
            quote(path),
            quote(path),
            quote(path)
        ))
    }
}

pub fn anchors(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_file_iter(path)?.collect::<std::result::Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(invalid("trust store is empty"));
    }
    Ok(certs)
}

pub fn crls(paths: &[PathBuf]) -> Result<Vec<CertificateRevocationListDer<'static>>> {
    let mut output = Vec::new();
    for path in paths {
        let entries = CertificateRevocationListDer::pem_file_iter(path)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if entries.is_empty() {
            return Err(invalid("required CRL file is empty"));
        }
        output.extend(entries);
    }
    Ok(output)
}

pub async fn resolve_target(origin: &Origin, rule: &Rule, denied: &[IpNet]) -> Result<SocketAddr> {
    let answers = tokio::net::lookup_host((origin.host(), origin.port())).await?;
    let mut unique = HashSet::new();
    let mut pinned = None;
    for address in answers {
        let ip = address.ip().to_canonical();
        if !unique.insert(ip) {
            continue;
        }
        if unique.len() > 64
            || denied.iter().any(|block| block.contains(&ip))
            || !permitted(ip, &rule.private_networks)
        {
            return Err(invalid("DNS answer outside site address policy"));
        }
        pinned.get_or_insert(SocketAddr::new(ip, origin.port()));
    }
    pinned.ok_or_else(|| invalid("destination resolved to no allowed addresses"))
}

fn permitted(ip: IpAddr, internal: &[IpNet]) -> bool {
    match ip {
        IpAddr::V4(v4) if v4.is_private() => internal.iter().any(|prefix| prefix.contains(&ip)),
        IpAddr::V4(v4) => public_ipv4(v4),
        IpAddr::V6(v6) if v6.is_unique_local() => {
            internal.iter().any(|prefix| prefix.contains(&ip))
        }
        IpAddr::V6(v6) => public_ipv6(v6),
    }
}
fn public_ipv4(v4: Ipv4Addr) -> bool {
    let [a, b, c, _] = v4.octets();
    // Reject special-use networks, including loopback, link-local, shared
    // address space, documentation, benchmarking, multicast and reserved.
    !matches!(
        (a, b, c),
        (0 | 127, _, _)
            | (169, 254, _)
            | (100, 64..=127, _)
            | (192, 0, 0 | 2)
            | (192, 88, 99)
            | (198, 18..=19, _)
            | (198, 51, 100)
            | (203, 0, 113)
            | (224..=255, _, _)
    )
}
fn public_ipv6(v6: Ipv6Addr) -> bool {
    let s = v6.segments();
    (s[0] & 0xe000 == 0x2000)
        && !matches!(
            (s[0], s[1]),
            (0x2001, 0..=0x1ff | 0xdb8) | (0x2002, _) | (0x3fff, 0..=0x0fff)
        )
}

pub fn publish_ca(path: &Path, pem: &str) -> io::Result<()> {
    use std::{io::Write, os::unix::fs::PermissionsExt};
    let temp = path.with_file_name(format!(".countersign-{}.tmp", uuid::Uuid::new_v4()));
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)?;
    let result = (|| {
        file.write_all(pem.as_bytes())?;
        file.set_permissions(fs::Permissions::from_mode(0o444))?;
        file.sync_all()?;
        fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}
