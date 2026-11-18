use countersign_gateway::{IssueError, SidecarIssuer};
use countersign_protocol::{ApprovalMode, DestinationEntry, DestinationPolicy, Origin};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, PublicKeyData};
use time::{Duration, OffsetDateTime};
use x509_parser::prelude::{GeneralName, parse_x509_certificate};

fn policy() -> DestinationPolicy {
    let entries = [
        (
            "restricted",
            "billing.example.test:443",
            ApprovalMode::ExactHost,
        ),
        (
            "services",
            "*.example.test:443",
            ApprovalMode::WholeWildcard,
        ),
        (
            "special",
            "billing.example.test:8443",
            ApprovalMode::ExactHost,
        ),
    ];
    DestinationPolicy::new(
        entries
            .into_iter()
            .map(|(id, pattern, mode)| DestinationEntry::new(id, 1, pattern, mode).unwrap())
            .collect(),
    )
    .unwrap()
}

fn after(hours: i64) -> OffsetDateTime {
    OffsetDateTime::now_utc() + Duration::hours(hours)
}

fn csr(key: &KeyPair, dns_names: &[&str]) -> Vec<u8> {
    let params =
        CertificateParams::new(dns_names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .unwrap();
    params.serialize_request(key).unwrap().der().to_vec()
}

#[test]
fn sidecar_generates_a_new_constrained_public_ca_each_launch() {
    let issuer = SidecarIssuer::new(policy(), after(3)).unwrap();
    let next = SidecarIssuer::new(policy(), after(3)).unwrap();
    let (_, ca) = parse_x509_certificate(issuer.public_cert_der()).unwrap();
    let (_, replacement) = parse_x509_certificate(next.public_cert_der()).unwrap();

    assert_ne!(ca.public_key().raw, replacement.public_key().raw);
    ca.verify_signature(None).unwrap();
    assert_eq!(ca.issuer(), ca.subject());
    let bc = ca.basic_constraints().unwrap().unwrap();
    assert!(bc.critical && bc.value.ca);
    assert_eq!(bc.value.path_len_constraint, Some(0));
    assert!(ca.key_usage().unwrap().unwrap().value.key_cert_sign());
    let constraints = ca.name_constraints().unwrap().unwrap();
    assert!(constraints.critical);
    let permitted = constraints.value.permitted_subtrees.as_ref().unwrap();
    assert_eq!(permitted.len(), 2);
    assert_eq!(
        permitted[0].base,
        GeneralName::DNSName("billing.example.test")
    );
    assert_eq!(permitted[1].base, GeneralName::DNSName("example.test"));
    let excluded = constraints.value.excluded_subtrees.as_ref().unwrap();
    assert_eq!(excluded.len(), 2);
    assert_eq!(excluded[0].base, GeneralName::IPAddress(&[0u8; 8]));
    assert_eq!(excluded[1].base, GeneralName::IPAddress(&[0u8; 32]));
    let pem = issuer.public_cert_pem();
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
    assert_eq!(pem.matches("-----BEGIN ").count(), 1);
}

#[test]
fn leaf_has_only_the_authorized_host_public_key_usage_and_lifetime() {
    let origin = Origin::parse("api.example.test:443").unwrap();
    let policy = policy();
    let scope = policy.scope_for(&origin).unwrap();
    let ca_limit = after(3);
    let issuer = SidecarIssuer::new(policy, ca_limit).unwrap();
    let (_, ca) = parse_x509_certificate(issuer.public_cert_der()).unwrap();
    let key = KeyPair::generate().unwrap();
    let request = csr(&key, &[origin.host()]);

    for grant_limit in [after(1), after(4)] {
        let der = issuer
            .issue(&scope, &origin, grant_limit, &request)
            .unwrap();
        let (_, leaf) = parse_x509_certificate(&der).unwrap();
        leaf.verify_signature(Some(ca.public_key())).unwrap();
        assert_eq!(leaf.issuer(), ca.subject());
        assert_eq!(leaf.public_key().raw, key.subject_public_key_info());
        assert!(!leaf.basic_constraints().unwrap().unwrap().value.ca);
        let usage = leaf.key_usage().unwrap().unwrap().value;
        assert!(usage.digital_signature() && !usage.key_cert_sign());
        let eku = leaf.extended_key_usage().unwrap().unwrap().value;
        assert!(eku.server_auth && !eku.client_auth && !eku.any);
        let names = &leaf
            .subject_alternative_name()
            .unwrap()
            .unwrap()
            .value
            .general_names;
        assert_eq!(names, &[GeneralName::DNSName(origin.host())]);
        assert_eq!(
            leaf.validity.not_after.timestamp(),
            grant_limit.min(ca_limit).unix_timestamp()
        );
        assert!(leaf.validity.is_valid());
    }
    assert!(matches!(
        issuer.issue(&scope, &origin, after(-1), &request),
        Err(IssueError::InvalidValidity)
    ));
}

#[test]
fn wildcard_grant_cannot_mint_leaves_for_other_ports_apex_or_overrides() {
    let api = Origin::parse("api.example.test:443").unwrap();
    let policy = policy();
    let scope = policy.scope_for(&api).unwrap();
    let issuer = SidecarIssuer::new(policy, after(3)).unwrap();
    let key = KeyPair::generate().unwrap();
    for authority in [
        "example.test:443",
        "api.example.test:8443",
        "billing.example.test:443",
        "a.b.example.test:443",
        "other.test:443",
    ] {
        let target = Origin::parse(authority).unwrap();
        assert!(
            matches!(
                issuer.issue(&scope, &target, after(1), &csr(&key, &[target.host()])),
                Err(IssueError::OutsideScope)
            ),
            "{authority}"
        );
    }
    let sibling = Origin::parse("search.example.test:443").unwrap();
    issuer
        .issue(&scope, &sibling, after(1), &csr(&key, &[sibling.host()]))
        .unwrap();
}

#[test]
fn requester_must_prove_key_possession_and_request_one_exact_dns_name() {
    let origin = Origin::parse("api.example.test:443").unwrap();
    let policy = policy();
    let scope = policy.scope_for(&origin).unwrap();
    let issuer = SidecarIssuer::new(policy, after(3)).unwrap();
    let key = KeyPair::generate().unwrap();
    let valid = csr(&key, &[origin.host()]);
    let mut corrupt = valid.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    let mut trailing = valid;
    trailing.push(0);
    let mut ca_request = CertificateParams::new(vec![origin.host().to_owned()]).unwrap();
    ca_request.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    for invalid in [
        corrupt,
        trailing,
        vec![],
        vec![0; 16 * 1024 + 1],
        csr(&key, &[]),
        csr(&key, &["*.example.test"]),
        csr(&key, &["another.example.test"]),
        csr(&key, &[origin.host(), "other.example.test"]),
        csr(&key, &[origin.host(), "127.0.0.1"]),
        ca_request.serialize_request(&key).unwrap().der().to_vec(),
    ] {
        assert!(matches!(
            issuer.issue(&scope, &origin, after(1), &invalid),
            Err(IssueError::InvalidRequest)
        ));
    }
}

#[test]
fn workload_tls_accepts_the_leaf_with_its_workers_private_key() {
    use std::sync::Arc;

    use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};
    use rustls_pki_types::{PrivatePkcs8KeyDer, ServerName};

    let origin = Origin::parse("api.example.test:443").unwrap();
    let policy = policy();
    let scope = policy.scope_for(&origin).unwrap();
    let issuer = SidecarIssuer::new(policy, after(3)).unwrap();
    let key = KeyPair::generate().unwrap();
    let leaf = issuer
        .issue(&scope, &origin, after(1), &csr(&key, &[origin.host()]))
        .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    roots.add(issuer.public_cert_der().clone()).unwrap();
    let client_config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.clone()],
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
    let mut client = ClientConnection::new(
        Arc::new(client_config),
        ServerName::try_from(origin.host().to_string()).unwrap(),
    )
    .unwrap();
    for _ in 0..8 {
        let mut client_flight = Vec::new();
        client.write_tls(&mut client_flight).unwrap();
        if !client_flight.is_empty() {
            server.read_tls(&mut client_flight.as_slice()).unwrap();
            server.process_new_packets().unwrap();
        }
        let mut server_flight = Vec::new();
        server.write_tls(&mut server_flight).unwrap();
        if !server_flight.is_empty() {
            client.read_tls(&mut server_flight.as_slice()).unwrap();
            client.process_new_packets().unwrap();
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            assert_eq!(client.peer_certificates().unwrap(), &[leaf]);
            return;
        }
    }
    panic!("TLS handshake did not finish in eight round trips");
}
