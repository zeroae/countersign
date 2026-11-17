//! Grant-scoped issuance for a shared Gateway. Only the supervisor owns an issuer.
use std::{collections::HashSet, error::Error, fs, path::PathBuf, sync::Arc, time::Duration};

use aws_sdk_acmpca::{
    Client,
    primitives::Blob,
    types::{SigningAlgorithm, Validity, ValidityPeriodType},
};
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
                let config = loader.load().await;
                let mut builder = aws_sdk_acmpca::config::Builder::from(&config);
                if let Some(url) = endpoint {
                    if !url.starts_with("https://") {
                        return Err("expected HTTPS issuer endpoint".into());
                    }
                    builder = builder.endpoint_url(url);
                }
                expected_uri = uri;
                Source::Remote {
                    client: Client::from_conf(builder.build()),
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
            || !cert
                .key_usage()?
                .is_some_and(|k| k.value.digital_signature() && !k.value.key_cert_sign())
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
