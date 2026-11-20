use std::collections::BTreeSet;

use countersign_protocol::{DestinationPolicy, DestinationScope, Origin};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, CidrSubnet, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, KeyPair, KeyUsagePurpose, NameConstraints,
    PKCS_ECDSA_P256_SHA256, PublicKeyData, SerialNumber, SubjectPublicKeyInfo,
};
use ring::rand::{SecureRandom, SystemRandom};
use rustls_pki_types::CertificateDer;
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::cri_attributes::ParsedCriAttribute;
use x509_parser::prelude::{FromDer, GeneralName, ParsedExtension, X509Version};

#[derive(Debug, Error)]
pub enum IssueError {
    #[error("the sidecar requires at least one protected DNS destination")]
    EmptyPolicy,
    #[error("the target is outside the approved destination scope")]
    OutsideScope,
    #[error("there is no remaining certificate validity")]
    InvalidValidity,
    #[error("invalid worker certificate request")]
    InvalidRequest,
    #[error("certificate generation failed")]
    Generation(#[from] rcgen::Error),
    #[error("cryptographic random source unavailable")]
    RandomUnavailable,
}

/// How long before it is issued a certificate's validity starts. A client
/// validates with its own clock, and one that runs behind the Gateway's would
/// otherwise find a fresh certificate not yet valid.
///
/// Why (2026-11-20): on ECS Fargate 1.4.0, kernel 6.1.190, curl in the
/// Gateway's own task rejected a leaf issued within 10 ms after a second began.
/// OpenSSL reads `time()`, which that kernel advances once per 10 ms tick, so
/// it still showed the second before the leaf's `notBefore`.
const CLIENT_CLOCK_ALLOWANCE: Duration = Duration::minutes(1);

/// One freshly generated CA and an immutable snapshot of its destination policy.
///
/// Only the public CA certificate and issued public leaves leave this object.
pub struct SidecarIssuer {
    authority: CertifiedIssuer<'static, KeyPair>,
    policy: DestinationPolicy,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
}

impl SidecarIssuer {
    pub fn new(
        policy: DestinationPolicy,
        ca_not_after: OffsetDateTime,
    ) -> Result<Self, IssueError> {
        let now = OffsetDateTime::now_utc();
        let not_after = certificate_deadline(now, ca_not_after)?;
        let suffixes: BTreeSet<&str> = policy
            .entries()
            .iter()
            .map(|entry| entry.constraint_dns_name())
            .collect();
        if suffixes.is_empty() {
            return Err(IssueError::EmptyPolicy);
        }

        let mut params = CertificateParams::default();
        params.not_before = now - CLIENT_CLOCK_ALLOWANCE;
        params.not_after = not_after;
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "Countersign sidecar CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        params.name_constraints = Some(NameConstraints {
            permitted_subtrees: suffixes
                .into_iter()
                .map(|s| GeneralSubtree::DnsName(s.to_owned()))
                .collect(),
            excluded_subtrees: vec![
                GeneralSubtree::IpAddress(CidrSubnet::V4([0; 4], [0; 4])),
                GeneralSubtree::IpAddress(CidrSubnet::V6([0; 16], [0; 16])),
            ],
        });
        let authority = CertifiedIssuer::self_signed(params, KeyPair::generate()?)?;
        Ok(Self {
            authority,
            policy,
            not_before: now,
            not_after,
        })
    }

    pub fn public_cert_der(&self) -> &CertificateDer<'static> {
        self.authority.der()
    }

    pub fn public_cert_pem(&self) -> String {
        self.authority.pem()
    }

    /// The trusted supervisor supplies the scope and deadline from its live grant.
    /// The worker supplies a PKCS#10 request for its ephemeral P-256 public key.
    /// A leaf is valid for one DNS name, even for a wildcard grant.
    pub fn issue(
        &self,
        scope: &DestinationScope,
        origin: &Origin,
        grant_not_after: OffsetDateTime,
        csr_der: &[u8],
    ) -> Result<CertificateDer<'static>, IssueError> {
        if !self.policy.covers(scope, origin) {
            return Err(IssueError::OutsideScope);
        }
        let now = OffsetDateTime::now_utc();
        if now < self.not_before {
            return Err(IssueError::InvalidValidity);
        }
        let not_after = certificate_deadline(now, grant_not_after.min(self.not_after))?;
        let public_key = verified_worker_key(origin.host(), csr_der)?;

        sign_leaf(origin, &public_key, now, not_after, &self.authority)
    }
}

pub(crate) fn sign_leaf(
    origin: &Origin,
    public_key: &SubjectPublicKeyInfo,
    now: OffsetDateTime,
    not_after: OffsetDateTime,
    authority: &rcgen::Issuer<'_, KeyPair>,
) -> Result<CertificateDer<'static>, IssueError> {
    let mut params = CertificateParams::new(vec![origin.host().to_owned()])?;
    params.not_before = now - CLIENT_CLOCK_ALLOWANCE;
    params.not_after = not_after;
    params.distinguished_name = DistinguishedName::new();
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.use_authority_key_identifier_extension = true;
    let mut serial = [0u8; 16];
    SystemRandom::new()
        .fill(&mut serial)
        .map_err(|_| IssueError::RandomUnavailable)?;
    serial[0] = (serial[0] & 0x7f) | 0x40;
    params.serial_number = Some(SerialNumber::from_slice(&serial));

    Ok(params.signed_by(public_key, authority)?.into())
}

fn certificate_deadline(
    now: OffsetDateTime,
    deadline: OffsetDateTime,
) -> Result<OffsetDateTime, IssueError> {
    // X.509 validity has whole-second precision. Never round a deadline up.
    let deadline = OffsetDateTime::from_unix_timestamp(deadline.unix_timestamp())
        .map_err(|_| IssueError::InvalidValidity)?;
    if deadline <= now || deadline.year() > 9999 {
        return Err(IssueError::InvalidValidity);
    }
    Ok(deadline)
}

pub(crate) fn verified_worker_key(
    host: &str,
    der: &[u8],
) -> Result<SubjectPublicKeyInfo, IssueError> {
    if der.len() > 16 * 1024 {
        return Err(IssueError::InvalidRequest);
    }
    let (rest, request) =
        X509CertificationRequest::from_der(der).map_err(|_| IssueError::InvalidRequest)?;
    let info = &request.certification_request_info;
    if !rest.is_empty() || info.version != X509Version::V1 {
        return Err(IssueError::InvalidRequest);
    }
    let [attribute] = info.attributes() else {
        return Err(IssueError::InvalidRequest);
    };
    let ParsedCriAttribute::ExtensionRequest(extensions) = attribute.parsed_attribute() else {
        return Err(IssueError::InvalidRequest);
    };
    let [extension] = extensions.extensions.as_slice() else {
        return Err(IssueError::InvalidRequest);
    };
    let ParsedExtension::SubjectAlternativeName(names) = extension.parsed_extension() else {
        return Err(IssueError::InvalidRequest);
    };
    if names.general_names.as_slice() != [GeneralName::DNSName(host)] {
        return Err(IssueError::InvalidRequest);
    }
    let key = SubjectPublicKeyInfo::from_der(info.subject_pki.raw)
        .map_err(|_| IssueError::InvalidRequest)?;
    if key.algorithm() != &PKCS_ECDSA_P256_SHA256 {
        return Err(IssueError::InvalidRequest);
    }
    request
        .verify_signature()
        .map_err(|_| IssueError::InvalidRequest)?;
    Ok(key)
}
