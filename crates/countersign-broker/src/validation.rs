//! Inputs are the selected public chain, administrator-installed anchors and
//! bounded local imports of signed status objects. No certificate URL is used.
pub(crate) use countersign_pki::Invalid;
use countersign_pki::{Result, Revocation, read_import};
use countersign_protocol::wire::{
    DistinguishedName, Fingerprint, IdentityHints, PublicChain, SignatureScheme,
};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, UnixTime, pem::PemObject},
    server::WebPkiClientVerifier,
};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use x509_parser::prelude::parse_x509_certificate;
#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Profile {
    ca_file: Option<PathBuf>,
    revocation: Option<Revocation>,
    /// An omitted map permits any valid identity under this entry's roots.
    /// When supplied, each user must have a listed leaf fingerprint.
    user_fingerprints: Option<BTreeMap<String, Vec<Fingerprint>>>,
}
pub(crate) struct Validator {
    anchors: Vec<CertificateDer<'static>>,
    roots: Arc<RootCertStore>,
    profile: Profile,
    issuers: Vec<DistinguishedName>,
}
pub(crate) struct Verdict {
    pub certificate_end: i64,
    pub evidence_end: i64,
    pub subject: String,
    pub issuer: String,
    pub leaf_end: i64,
}
impl Validator {
    pub(crate) fn new(profile: Profile, default_ca: &Path) -> Result<Self> {
        if let Some(r) = &profile.revocation {
            let files = match r {
                Revocation::Crl { files } | Revocation::Ocsp { files, .. } => files,
            };
            if files.is_empty() || files.len() > 32 {
                return Err(Invalid::Evidence);
            }
        }
        let bytes = read_import(profile.ca_file.as_deref().unwrap_or(default_ca))?;
        let anchors = CertificateDer::pem_slice_iter(&bytes)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| Invalid::Evidence)?;
        if anchors.is_empty()
            || anchors.len() > 64
            || profile
                .user_fingerprints
                .as_ref()
                .is_some_and(|m| m.values().any(|v| v.len() > 256))
        {
            return Err(Invalid::Evidence);
        }
        let mut roots = RootCertStore::empty();
        let mut issuers = Vec::new();
        for anchor in &anchors {
            let (_, ca) = parse_x509_certificate(anchor.as_ref()).map_err(|_| Invalid::Evidence)?;
            issuers.push(
                DistinguishedName::new(ca.subject().as_raw().to_owned())
                    .map_err(|_| Invalid::Evidence)?,
            );
            roots.add(anchor.clone()).map_err(|_| Invalid::Evidence)?;
        }
        Ok(Self {
            anchors,
            issuers,
            roots: Arc::new(roots),
            profile,
        })
    }
    pub(crate) fn hints(&self, user: &str) -> IdentityHints {
        use SignatureScheme::*;
        IdentityHints {
            issuer_names: self.issuers.clone(),
            cert_fingerprints: self
                .profile
                .user_fingerprints
                .as_ref()
                .map(|m| m.get(user).cloned().unwrap_or_default()),
            signature_schemes: vec![
                EcdsaNistp256Sha256,
                EcdsaNistp384Sha384,
                RsaPssSha256,
                RsaPssSha384,
                RsaPssSha512,
                RsaPkcs1Sha256,
                RsaPkcs1Sha384,
                RsaPkcs1Sha512,
            ],
        }
    }
    pub(crate) fn verify(&self, user: &str, chain: &PublicChain, at: u64) -> Result<Verdict> {
        let now = (at / 1000) as i64;
        let ders: Vec<_> = chain
            .as_slice()
            .iter()
            .map(|b| CertificateDer::from(b.as_slice()))
            .collect();
        let (leaf, rest) = ders.split_first().ok_or(Invalid::Evidence)?;
        let (_, client) = parse_x509_certificate(leaf.as_ref()).map_err(|_| Invalid::Evidence)?;
        if client.is_ca()
            || client
                .key_usage()
                .map_err(|_| Invalid::Evidence)?
                .is_some_and(|ku| !ku.value.digital_signature())
        {
            return Err(Invalid::Evidence);
        }
        use x509_parser::public_key::PublicKey;
        let supported = match client
            .public_key()
            .parsed()
            .map_err(|_| Invalid::Evidence)?
        {
            PublicKey::RSA(rsa) => (2048..=8192).contains(&rsa.key_size()),
            PublicKey::EC(_) => client
                .public_key()
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok())
                .is_some_and(|oid| {
                    matches!(
                        oid.to_id_string().as_str(),
                        "1.2.840.10045.3.1.7" | "1.3.132.0.34"
                    )
                }),
            _ => false,
        };
        if !supported {
            return Err(Invalid::Evidence);
        }
        let hash = crate::credentials::fingerprint(leaf.as_ref());
        if self.profile.user_fingerprints.as_ref().is_some_and(|m| {
            !m.get(user)
                .is_some_and(|values| values.iter().any(|v| v.0 == hash))
        }) {
            return Err(Invalid::Evidence);
        }
        let mut until = i64::MAX;
        let mut verifier = WebPkiClientVerifier::builder_with_provider(
            self.roots.clone(),
            Arc::new(rustls::crypto::ring::default_provider()),
        );
        if let Some(Revocation::Crl { files }) = &self.profile.revocation {
            let (crls, end) = countersign_pki::crls(files, now)?;
            until = end;
            verifier = verifier.with_crls(crls).enforce_revocation_expiration();
        }
        let verifier = verifier.build().map_err(|_| Invalid::Evidence)?;
        verifier
            .verify_client_cert(
                leaf,
                rest,
                UnixTime::since_unix_epoch(Duration::from_millis(at)),
            )
            .map_err(|e| {
                if matches!(
                    e,
                    rustls::Error::InvalidCertificate(rustls::CertificateError::Revoked)
                ) {
                    Invalid::Revoked
                } else {
                    Invalid::Evidence
                }
            })?;
        let mut cert_end = i64::MAX;
        for cert in &ders {
            let (rest, x) = parse_x509_certificate(cert.as_ref()).map_err(|_| Invalid::Evidence)?;
            if !rest.is_empty() {
                return Err(Invalid::Evidence);
            }
            cert_end = cert_end.min(x.validity.not_after.timestamp());
        }
        if let Some(Revocation::Ocsp { files, max_age_s }) = &self.profile.revocation {
            until = countersign_pki::validate_ocsp(&ders, &self.anchors, files, *max_age_s, now)?;
        }
        Ok(Verdict {
            certificate_end: cert_end,
            evidence_end: cert_end.min(until),
            subject: client.subject().to_string(),
            issuer: client.issuer().to_string(),
            leaf_end: client.validity.not_after.timestamp(),
        })
    }
}

#[cfg(test)]
mod tests;
