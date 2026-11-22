use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use countersign_protocol::{
    ApprovalMode, DestinationEntry, DestinationPolicy, Origin, wire::WorkloadBinding,
};
use ipnet::IpNet;
use rustls_pki_types::{CertificateDer, pem::PemObject};
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
    /// The HTTP proxy every destination goes through, unless its rule says
    /// `"egress": "direct"` (ADR 0003).
    #[serde(rename = "egress_proxy")]
    egress_proxy_url: Option<String>,
    #[serde(skip)]
    pub egress_proxy: Option<EgressProxy>,
    #[serde(default)]
    pub denied_networks: Vec<IpNet>,
    pub shared: Option<Shared>,
    #[serde(default)]
    pub worker_sandbox: WorkerSandbox,
    /// Conservative upper bound on the difference between Broker and Gateway
    /// UTC. The operator must maintain synchronized clocks.
    #[serde(default = "default_uncertainty")]
    pub clock_uncertainty_ms: u64,
}

/// The worker sandbox the operator chose (ADR 0001). The Gateway runs every
/// grant worker under it, and never under the other one.
#[derive(Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum WorkerSandbox {
    /// The base layers inside bubblewrap's namespaces.
    #[default]
    Namespaces,
    /// The base layers alone, for a host that refuses namespaces.
    Filter,
}

impl WorkerSandbox {
    /// The layer the supervisor adds around the base layers, when it adds one.
    pub fn outer_layer(self) -> Option<&'static str> {
        match self {
            WorkerSandbox::Namespaces => Some("namespaces"),
            WorkerSandbox::Filter => None,
        }
    }
}

impl fmt::Display for WorkerSandbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            WorkerSandbox::Namespaces => "namespaces",
            WorkerSandbox::Filter => "filter",
        })
    }
}

/// The egress proxy's address, as the operator wrote it: a name or an IP
/// literal, resolved on every connection.
#[derive(Debug, Clone)]
pub(crate) struct EgressProxy {
    pub host: String,
    pub port: u16,
}

impl EgressProxy {
    fn parse(url: &str) -> Result<Self> {
        let shape = || {
            invalid(
                "egress_proxy must be an http URL with a host and a port, such as http://proxy.internal:3128",
            )
        };
        let parsed = reqwest::Url::parse(url).map_err(|_| shape())?;
        if parsed.scheme() == "https" {
            return Err(invalid(
                "egress_proxy must be an http URL: the Gateway sends CONNECT to the egress proxy in plain text and does not support an https egress proxy",
            ));
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(invalid(
                "egress_proxy must not carry credentials: the Gateway does not authenticate to the egress proxy",
            ));
        }
        // The URL parser forgets a port it knows as the default, so look for
        // one in the text: after the host, outside an IPv6 literal's brackets.
        let authority = url
            .split_once("://")
            .map_or("", |(_, rest)| rest)
            .split(['/', '?', '#'])
            .next()
            .unwrap_or_default();
        let written_port = authority
            .rsplit(']')
            .next()
            .and_then(|tail| tail.rsplit_once(':'))
            .is_some_and(|(_, port)| !port.is_empty());
        let (Some(host), Some(port)) = (parsed.host_str(), parsed.port_or_known_default()) else {
            return Err(shape());
        };
        if parsed.scheme() != "http"
            || !written_port
            || port == 0
            || parsed.path() != "/"
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(shape());
        }
        Ok(Self {
            host: host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_owned(),
            port,
        })
    }
}

impl fmt::Display for EgressProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
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
    #[serde(default)]
    pub egress: Egress,
    pub roots: PathBuf,
    #[serde(default)]
    pub revocation: Option<countersign_pki::Revocation>,
}

/// A destination's route to the site (ADR 0003).
#[derive(Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Egress {
    /// Through the egress proxy when the Gateway has one, else direct. The
    /// operator never writes it: it is what a rule without `egress` means.
    #[default]
    #[serde(skip_deserializing)]
    Default,
    /// Always direct, with the Gateway's own address policy.
    Direct,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let mut config: Self = serde_json::from_slice(&fs::read(path)?)?;
        config.egress_proxy = config
            .egress_proxy_url
            .as_deref()
            .map(EgressProxy::parse)
            .transpose()?;
        if let Some(rule) = config.destinations.iter().find(|rule| {
            config.egress_proxy_for(rule).is_some() && !rule.private_networks.is_empty()
        }) {
            return Err(io::Error::other(format!(
                "destination rule {:?} has private_networks and goes through the egress proxy, which does not check them: remove private_networks, or set \"egress\": \"direct\" on the rule",
                rule.id
            ))
            .into());
        }
        let sidecar = config.shared.is_none();
        if config.workload.is_some() != sidecar
            || config.workload_token.is_some() != sidecar
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

    /// The egress proxy this rule's destinations go through, if any.
    pub fn egress_proxy_for(&self, rule: &Rule) -> Option<&EgressProxy> {
        match rule.egress {
            Egress::Direct => None,
            Egress::Default => self.egress_proxy.as_ref(),
        }
    }

    /// Which destinations leave their address policy to the egress proxy, in
    /// words for the startup log.
    pub fn left_to_egress_proxy(&self) -> String {
        let ids = self
            .destinations
            .iter()
            .filter(|rule| self.egress_proxy_for(rule).is_some())
            .map(|rule| rule.id.as_str())
            .collect::<Vec<_>>();
        if ids.is_empty() {
            "carries the address policy of no destination".to_owned()
        } else {
            format!(
                "carries the address policy of destinations: {}",
                ids.join(", ")
            )
        }
    }

    pub fn policy(&self) -> Result<DestinationPolicy> {
        if self
            .destinations
            .iter()
            .any(|rule| rule.pattern.starts_with("*.") && !rule.private_networks.is_empty())
        {
            return Err(invalid(
                "private egress requires an exact host and prefix rule",
            ));
        }
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
    let bytes = countersign_pki::read_import(path)?;
    let certs =
        CertificateDer::pem_slice_iter(&bytes).collect::<std::result::Result<Vec<_>, _>>()?;
    if certs.is_empty() || certs.len() > 64 {
        return Err(invalid("invalid trust store size"));
    }
    Ok(certs)
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
    // Private routes pin *all* answers to the configured prefixes. The
    // cloud infrastructure endpoints below remain forbidden on private routes.
    if !internal.is_empty() && !internal.iter().any(|prefix| prefix.contains(&ip)) {
        return false;
    }
    if matches!(ip, IpAddr::V4(v) if v.octets()==[168,63,129,16])
        || matches!(ip, IpAddr::V6(v) if matches!(v.segments(), [0xfd00,0xec2,0,0,0,0,0,0x254|0x253|0x23] | [0xfd20,0xce,0,0,0,0,0,0x254]))
    {
        return false;
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn infrastructure_is_denied_even_with_private_prefixes() {
        let prefixes = ["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()];
        for addr in [
            "127.0.0.1",
            "169.254.169.254",
            "::ffff:169.254.169.254",
            "fd00:ec2::254",
            "fd20:ce::254",
            "168.63.129.16",
            "224.0.0.1",
            "100.100.100.200",
            "fe80::1",
            "::",
            "::1",
        ] {
            assert!(
                !permitted(addr.parse::<IpAddr>().unwrap().to_canonical(), &prefixes),
                "{addr}"
            );
        }
        let private = ["10.100.0.0/24".parse().unwrap()];
        assert!(permitted("10.100.0.9".parse().unwrap(), &private));
        assert!(!permitted("10.101.0.9".parse().unwrap(), &private));
        assert!(!permitted("8.8.8.8".parse().unwrap(), &private));
        assert!(!permitted("10.100.0.9".parse().unwrap(), &[]));
    }
}
