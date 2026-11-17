//! Grant-scoped issuance for a shared Gateway. Only the supervisor owns an issuer.
use std::{collections::HashSet, error::Error, fs, path::PathBuf, sync::Arc, time::Duration};

use aws_sdk_acmpca::{
    Client,
    primitives::Blob,
    types::{SigningAlgorithm, Validity, ValidityPeriodType},
};
use aws_smithy_json::protocol::aws_json_rpc::AwsJsonRpcProtocol;
use countersign_protocol::{DestinationPolicy, DestinationScope, Origin};
use rcgen::{Issuer, KeyPair, PublicKeyData};
use rustls::{
    RootCertStore,
    client::{WebPkiServerVerifier, danger::ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime, pem::PemObject},
};
use serde::Deserialize;
use time::OffsetDateTime;
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

use crate::sidecar::{sign_leaf, verified_worker_key};

type Failure = Box<dyn Error + Send + Sync>;
type Chain = Vec<CertificateDer<'static>>;

#[derive(Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SharedCaSource {
    Local {
        cert: PathBuf,
        key: PathBuf,
    },
    AcmPca {
        region: String,
        profile: Option<String>,
        endpoint: Option<String>,
        ca_arn: String,
        template: String,
        signing_algorithm: String,
        roots: PathBuf,
        expected_uri: Option<String>,
    },
}

enum Source {
    Local {
        issuer: Box<Issuer<'static, KeyPair>>,
        chain: Chain,
        expires: OffsetDateTime,
    },
    Remote {
        client: Client,
        ca: String,
        template: String,
        algorithm: SigningAlgorithm,
    },
}

pub struct SharedIssuer {
    source: Source,
    verifier: Arc<WebPkiServerVerifier>,
    policy: DestinationPolicy,
    expected_uri: Option<String>,
}

async fn issuer_client(
    loader: aws_config::ConfigLoader,
    endpoint: Option<&str>,
) -> Result<Client, Failure> {
    let config = loader.load().await;
    let mut builder =
        aws_sdk_acmpca::config::Builder::from(&config).protocol(AwsJsonRpcProtocol::aws_json_1_1());
    // The shared AWS config spells this service key acm_pca. The pinned
    // SDK otherwise normalizes "ACM PCA" to acm-pca in a services block.
    let service_key = aws_types::service_config::ServiceConfigKey::builder()
        .service_id("ACM_PCA")
        .env("AWS_ENDPOINT_URL")
        .profile("endpoint_url")
        .build()?;
    let configured = config
        .service_config()
        .and_then(|source| source.load_config(service_key));
    if let Some(endpoint) = endpoint.or(configured.as_deref()) {
        let url = reqwest::Url::parse(endpoint)?;
        if url.scheme() != "https"
            || url.host().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err("expected an HTTPS issuer endpoint".into());
        }
        builder = builder.endpoint_url(endpoint);
    }
    Ok(Client::from_conf(builder.build()))
}

impl SharedIssuer {
    pub async fn open(config: SharedCaSource, policy: DestinationPolicy) -> Result<Self, Failure> {
        let mut roots = RootCertStore::empty();
        let mut expected_uri = None;
        let source = match config {
            SharedCaSource::Local { cert, key } => {
                let chain = CertificateDer::pem_file_iter(cert)?.collect::<Result<Chain, _>>()?;
                let ca = chain.first().ok_or("empty CA chain")?;
                let (_, parsed) = X509Certificate::from_der(ca)?;
                let key = KeyPair::from_pem(&fs::read_to_string(key)?)?;
                if !parsed.is_ca()
                    || !parsed.validity().is_valid()
                    || !parsed.key_usage()?.is_some_and(|u| u.value.key_cert_sign())
                    || parsed.public_key().raw != key.subject_public_key_info()
                {
                    return Err("invalid proxy CA credential".into());
                }
                let expires = parsed.validity.not_after.to_datetime();
                let issuer = Box::new(Issuer::from_ca_cert_der(ca, key)?);
                roots.add(chain.last().ok_or("empty CA chain")?.clone())?;
                Source::Local {
                    issuer,
                    chain,
                    expires,
                }
            }
            SharedCaSource::AcmPca {
                profile,
                region,
                endpoint,
                ca_arn,
                template,
                roots: anchors,
                signing_algorithm,
                expected_uri: uri,
            } => {
                for cert in CertificateDer::pem_file_iter(anchors)? {
                    roots.add(cert?)?;
                }
                let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
                    .region(aws_sdk_acmpca::config::Region::new(region));
                if let Some(name) = profile {
                    loader = loader.profile_name(name);
                }
                let client = issuer_client(loader, endpoint.as_deref()).await?;
                expected_uri = uri;
                Source::Remote {
                    client,
                    ca: ca_arn,
                    template,
                    algorithm: SigningAlgorithm::from(signing_algorithm.as_str()),
                }
            }
        };
        let verifier = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()?;
        Ok(Self {
            source,
            verifier,
            policy,
            expected_uri,
        })
    }

    pub async fn issue(
        &self,
        scope: &DestinationScope,
        origin: &Origin,
        grant_not_after: OffsetDateTime,
        csr_der: &[u8],
        grant_version_id: &str,
    ) -> Result<Chain, Failure> {
        if !self.policy.covers(scope, origin) {
            return Err("outside grant scope".into());
        }
        let now = OffsetDateTime::now_utc();
        let remaining = Duration::try_from(grant_not_after - now)?;
        if remaining.as_secs() == 0 {
            return Err("grant has expired".into());
        }
        let key = verified_worker_key(origin.host(), csr_der)?;
        let chain = match &self.source {
            Source::Local {
                issuer,
                chain,
                expires,
            } => {
                let deadline = grant_not_after.min(*expires);
                if deadline.unix_timestamp() <= now.unix_timestamp() {
                    return Err("issuer has expired".into());
                }
                let leaf = sign_leaf(origin, &key, now, deadline, issuer)?;
                std::iter::once(leaf).chain(chain.iter().cloned()).collect()
            }
            Source::Remote {
                client,
                ca,
                template,
                algorithm,
            } => {
                let deadline = grant_not_after.unix_timestamp();
                let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
                for field in [
                    ca.as_bytes(),
                    template.as_bytes(),
                    grant_version_id.as_bytes(),
                    origin.to_string().as_bytes(),
                    &deadline.to_be_bytes(),
                    csr_der,
                ] {
                    hash.update(&(field.len() as u64).to_be_bytes());
                    hash.update(field);
                }
                let token: String = hash.finish().as_ref()[..16]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                let validity = Validity::builder()
                    .r#type(ValidityPeriodType::Absolute)
                    .value(deadline)
                    .build()?;
                let operation = async {
                    let issued = client
                        .issue_certificate()
                        .certificate_authority_arn(ca)
                        .template_arn(template)
                        .signing_algorithm(algorithm.clone())
                        .csr(Blob::new(pem::encode(&pem::Pem::new(
                            "CERTIFICATE REQUEST",
                            csr_der,
                        ))))
                        .validity(validity)
                        .idempotency_token(token)
                        .send()
                        .await?;
                    let arn = issued
                        .certificate_arn()
                        .ok_or("issuer omitted certificate identifier")?;
                    if !arn
                        .strip_prefix(ca)
                        .and_then(|suffix| suffix.strip_prefix("/certificate/"))
                        .is_some_and(|serial| !serial.is_empty() && !serial.contains('/'))
                    {
                        return Err("certificate identifier belongs to another CA".into());
                    }
                    loop {
                        match client
                            .get_certificate()
                            .certificate_authority_arn(ca)
                            .certificate_arn(arn)
                            .send()
                            .await
                        {
                            Ok(reply) => {
                                let mut chain = vec![CertificateDer::from_pem_slice(
                                    reply
                                        .certificate()
                                        .ok_or("issuer omitted certificate")?
                                        .as_bytes(),
                                )?];
                                if let Some(pem) = reply.certificate_chain() {
                                    chain.extend(
                                        CertificateDer::pem_slice_iter(pem.as_bytes())
                                            .collect::<Result<Chain, _>>()?,
                                    );
                                }
                                return Ok::<_, Failure>(chain);
                            }
                            Err(err)
                                if err
                                    .as_service_error()
                                    .is_some_and(|e| e.is_request_in_progress_exception()) =>
                            {
                                tokio::time::sleep(Duration::from_millis(250)).await
                            }
                            Err(e) => return Err(e.into()),
                        }
                    }
                };
                tokio::time::timeout(remaining.min(Duration::from_secs(30)), operation).await??
            }
        };
        let leaf = chain.first().ok_or("missing signed certificate")?;
        let (rest, cert) = X509Certificate::from_der(leaf)?;
        let ext = cert.extended_key_usage()?.ok_or("missing leaf EKU")?.value;
        let names = cert.subject_alternative_name()?.ok_or("missing SAN")?.value;
        let exact_name = GeneralName::DNSName(origin.host());
        let expected = std::iter::once(exact_name)
            .chain(self.expected_uri.as_deref().map(GeneralName::URI))
            .collect::<Vec<_>>();
        let mut seen = HashSet::new();
        if cert
            .extensions()
            .iter()
            .any(|ext| !seen.insert(ext.oid.clone()))
            || !rest.is_empty()
            || cert.is_ca()
            || !ext.server_auth
            || ext.any
            || ext.client_auth
            || ext.code_signing
            || ext.email_protection
            || ext.time_stamping
            || ext.ocsp_signing
            || !ext.other.is_empty()
            || !cert.key_usage()?.is_some_and(|k| {
                k.value.digital_signature() && !k.value.key_cert_sign() && !k.value.crl_sign()
            })
            || names.general_names.len() != expected.len()
            || expected
                .iter()
                .any(|name| !names.general_names.contains(name))
            || cert.validity.not_after.timestamp() > grant_not_after.unix_timestamp()
            || cert.public_key().raw != key.subject_public_key_info()
        {
            return Err("issuer returned a certificate outside the approved profile".into());
        }
        self.verifier.verify_server_cert(
            leaf,
            &chain[1..],
            &ServerName::try_from(origin.host())?,
            &[],
            UnixTime::now(),
        )?;
        Ok(chain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_acmpca::config::{BehaviorVersion, Credentials, Region};
    use aws_smithy_http_client::test_util::{ReplayEvent, StaticReplayClient};
    use aws_smithy_types::body::SdkBody;
    use countersign_protocol::{ApprovalMode, DestinationEntry};
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose,
    };
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};
    use serde_json::{Value, json};
    use tempfile::tempdir;

    const CA: &str = "arn:private:service:region:account:certificate-authority/example";

    struct TestSite {
        origin: Origin,
        scope: DestinationScope,
        policy: DestinationPolicy,
        key: KeyPair,
        csr: Vec<u8>,
        ca: CertificateDer<'static>,
        ca_key: KeyPair,
        deadline: OffsetDateTime,
    }
    impl TestSite {
        fn new() -> Self {
            let origin = Origin::parse("sample.test:443").unwrap();
            let policy = DestinationPolicy::new(vec![
                DestinationEntry::new("site", 1, &origin.to_string(), ApprovalMode::ExactHost)
                    .unwrap(),
            ])
            .unwrap();
            let scope = policy.scope_for(&origin).unwrap();
            let key = KeyPair::generate().unwrap();
            let csr = CertificateParams::new(vec![origin.host().to_owned()])
                .unwrap()
                .serialize_request(&key)
                .unwrap()
                .der()
                .to_vec();
            let mut params = CertificateParams::default();
            params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
            let ca_key = KeyPair::generate().unwrap();
            let ca = params.self_signed(&ca_key).unwrap().der().clone();
            Self {
                origin,
                scope,
                policy,
                key,
                csr,
                ca,
                ca_key,
                deadline: OffsetDateTime::now_utc() + time::Duration::minutes(3),
            }
        }
        fn roots(&self) -> RootCertStore {
            let mut roots = RootCertStore::empty();
            roots.add(self.ca.clone()).unwrap();
            roots
        }
        fn leaf_pem(&self, extra_name: bool) -> String {
            let mut names = vec![self.origin.host().to_owned()];
            if extra_name {
                names.push("other.test".into());
            }
            let mut p = CertificateParams::new(names).unwrap();
            p.not_after = self.deadline;
            p.is_ca = IsCa::ExplicitNoCa;
            p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            let issuer = Issuer::from_ca_cert_der(
                &self.ca,
                KeyPair::from_pem(&self.ca_key.serialize_pem()).unwrap(),
            )
            .unwrap();
            p.signed_by(&self.key, &issuer).unwrap().pem()
        }
        fn tls(&self, chain: Chain) {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let c = ClientConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(self.roots())
                .with_no_client_auth();
            let s = ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    chain,
                    PrivatePkcs8KeyDer::from(self.key.serialize_der()).into(),
                )
                .unwrap();
            let mut client = ClientConnection::new(
                Arc::new(c),
                ServerName::try_from(self.origin.host().to_owned()).unwrap(),
            )
            .unwrap();
            let mut server = ServerConnection::new(Arc::new(s)).unwrap();
            for _ in 0..8 {
                let mut flight = Vec::new();
                client.write_tls(&mut flight).unwrap();
                server.read_tls(&mut &flight[..]).unwrap();
                server.process_new_packets().unwrap();
                flight.clear();
                server.write_tls(&mut flight).unwrap();
                client.read_tls(&mut &flight[..]).unwrap();
                client.process_new_packets().unwrap();
                if !client.is_handshaking() && !server.is_handshaking() {
                    return;
                }
            }
            panic!("issued leaf did not complete a handshake");
        }
        fn remote(&self, extra_name: bool) -> (SharedIssuer, StaticReplayClient) {
            let event = |status: u16, body: Value| {
                ReplayEvent::new(
                    hyper::http::Request::builder()
                        .uri("https://pca.example/")
                        .body(SdkBody::empty())
                        .unwrap(),
                    hyper::http::Response::builder()
                        .status(status)
                        .header("content-type", "application/x-amz-json-1.1")
                        .body(SdkBody::from(body.to_string()))
                        .unwrap(),
                )
            };
            let http = StaticReplayClient::new(vec![
                event(200, json!({"CertificateArn":format!("{CA}/certificate/1")})),
                event(
                    400,
                    json!({"__type":"RequestInProgressException","message":"still issuing"}),
                ),
                event(200, json!({"Certificate":self.leaf_pem(extra_name)})),
            ]);
            let sdk = aws_sdk_acmpca::Config::builder()
                .protocol(AwsJsonRpcProtocol::aws_json_1_1())
                .behavior_version(BehaviorVersion::latest())
                .http_client(http.clone())
                .region(Region::new("us-east-1"))
                .endpoint_url("https://pca.example")
                .credentials_provider(Credentials::new("test", "test", None, None, "test"))
                .build();
            let verifier = WebPkiServerVerifier::builder_with_provider(
                Arc::new(self.roots()),
                Arc::new(rustls::crypto::ring::default_provider()),
            )
            .build()
            .unwrap();
            (
                SharedIssuer {
                    source: Source::Remote {
                        client: Client::from_conf(sdk),
                        ca: CA.into(),
                        template: "template".into(),
                        algorithm: SigningAlgorithm::Sha256Withecdsa,
                    },
                    verifier,
                    policy: self.policy.clone(),
                    expected_uri: None,
                },
                http,
            )
        }
    }

    #[tokio::test]
    async fn local_shared_ca_checks_key_and_issues_for_tls() {
        let site = TestSite::new();
        let dir = tempdir().unwrap();
        let cert = dir.path().join("ca.pem");
        let key = dir.path().join("key.pem");
        fs::write(
            &cert,
            pem::encode(&pem::Pem::new("CERTIFICATE", site.ca.as_ref())),
        )
        .unwrap();
        fs::write(&key, site.ca_key.serialize_pem()).unwrap();
        let source = SharedCaSource::Local {
            cert,
            key: key.clone(),
        };
        let issuer = SharedIssuer::open(source.clone(), site.policy.clone())
            .await
            .unwrap();
        let chain = issuer
            .issue(&site.scope, &site.origin, site.deadline, &site.csr, "g/1")
            .await
            .unwrap();
        site.tls(chain);
        fs::write(key, KeyPair::generate().unwrap().serialize_pem()).unwrap();
        assert!(SharedIssuer::open(source, site.policy).await.is_err());
    }

    #[tokio::test]
    async fn shared_profile_selects_acm_pca_service_endpoint() {
        use aws_runtime::env_config::file::{EnvConfigFileKind, EnvConfigFiles};
        const PROFILE: &str = "[profile proxy]\nregion=us-east-1\nservices=local\n\n[services local]\nacm_pca =\n  endpoint_url = https://issuer.example/\n";
        for (explicit, target) in [
            (None, "https://issuer.example/"),
            (
                Some("https://override.example"),
                "https://override.example/",
            ),
        ] {
            let http = StaticReplayClient::new(vec![ReplayEvent::new(
                hyper::http::Request::builder()
                    .uri(target)
                    .body(SdkBody::empty())
                    .unwrap(),
                hyper::http::Response::builder()
                    .status(200)
                    .body(SdkBody::from("{}"))
                    .unwrap(),
            )]);
            let files = EnvConfigFiles::builder()
                .with_contents(EnvConfigFileKind::Config, PROFILE)
                .build();
            let loader = aws_config::defaults(BehaviorVersion::latest())
                .profile_files(files)
                .profile_name("proxy")
                .http_client(http.clone())
                .credentials_provider(Credentials::new(
                    "fixture", "fixture", None, None, "fixture",
                ));
            let client = issuer_client(loader, explicit).await.unwrap();
            client
                .describe_certificate_authority()
                .certificate_authority_arn(CA)
                .send()
                .await
                .unwrap();
            assert_eq!(http.actual_requests().next().unwrap().uri(), target);
        }
    }

    #[tokio::test]
    async fn sdk_issues_and_retrieves_exact_certificate_before_tls() {
        let site = TestSite::new();
        let (issuer, http) = site.remote(false);
        let chain = issuer
            .issue(&site.scope, &site.origin, site.deadline, &site.csr, "g/1")
            .await
            .unwrap();
        site.tls(chain);
        let calls = http
            .actual_requests()
            .map(|r| {
                assert_eq!(r.uri(), "https://pca.example/");
                assert!(
                    r.headers()
                        .get("authorization")
                        .unwrap()
                        .starts_with("AWS4-HMAC-SHA256 ")
                );
                serde_json::from_slice::<Value>(r.body().bytes().unwrap()).unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0]["CertificateAuthorityArn"], CA);
        assert_eq!(calls[0]["TemplateArn"], "template");
        assert_eq!(calls[0]["Validity"]["Type"], "ABSOLUTE");
        assert_eq!(
            calls[0]["Validity"]["Value"],
            site.deadline.unix_timestamp()
        );
        assert_eq!(calls[1], calls[2]);
        let (issuer, _) = site.remote(true);
        assert!(
            issuer
                .issue(&site.scope, &site.origin, site.deadline, &site.csr, "g/1")
                .await
                .is_err()
        );
    }
}
