//! Inputs are the selected public chain, administrator-installed anchors and
//! bounded local imports of signed status objects. No certificate URL is used.
use countersign_protocol::wire::{Fingerprint, PublicChain};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, CertificateRevocationListDer, UnixTime, pem::PemObject},
    server::WebPkiClientVerifier,
};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    fs::File,
    io::Read,
    num::NonZeroU32,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use x509_parser::prelude::{parse_x509_certificate, parse_x509_crl};
mod ocsp;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum Invalid {
    #[error("invalid certificate chain, trust profile or status evidence")]
    Evidence,
    #[error("certificate revoked")]
    Revoked,
}
type Result<T> = std::result::Result<T, Invalid>;

#[derive(Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Revocation {
    Crl {
        files: Vec<PathBuf>,
    },
    Ocsp {
        files: Vec<PathBuf>,
        max_age_s: Option<NonZeroU32>,
    },
}
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
}
pub(crate) struct Verdict {
    pub certificate_end: i64,
    pub evidence_end: i64,
}
fn read_import(path: &Path) -> Result<Vec<u8>> {
    const MAX: u64 = 4 * 1024 * 1024;
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| Invalid::Evidence)?
        .take(MAX + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Invalid::Evidence)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX {
        return Err(Invalid::Evidence);
    }
    Ok(bytes)
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
        if anchors.is_empty() {
            return Err(Invalid::Evidence);
        }
        let mut roots = RootCertStore::empty();
        for anchor in &anchors {
            roots.add(anchor.clone()).map_err(|_| Invalid::Evidence)?;
        }
        Ok(Self {
            anchors,
            roots: Arc::new(roots),
            profile,
        })
    }
    pub(crate) fn verify(&self, user: &str, chain: &PublicChain, at: u64) -> Result<Verdict> {
        let now = (at / 1000) as i64;
        let ders: Vec<_> = chain
            .as_slice()
            .iter()
            .map(|b| CertificateDer::from(b.as_slice()))
            .collect();
        let (leaf, rest) = ders.split_first().ok_or(Invalid::Evidence)?;
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
            let mut crls = Vec::new();
            let mut issuers = std::collections::HashSet::new();
            for file in files {
                let bytes = read_import(file)?;
                let (trailing, crl) = parse_x509_crl(&bytes).map_err(|_| Invalid::Evidence)?;
                // Only one complete direct CRL per issuer is supported. An
                // overlapping or partial CRL must never hide a revoked serial.
                if !issuers.insert(crl.issuer().as_raw().to_vec())
                    || crl
                        .extensions()
                        .iter()
                        .any(|e| matches!(e.oid.to_string().as_str(), "2.5.29.27" | "2.5.29.28"))
                    || crl.iter_revoked_certificates().any(|r| {
                        r.extensions()
                            .iter()
                            .any(|e| e.oid.to_string() == "2.5.29.29")
                    })
                {
                    return Err(Invalid::Evidence);
                }
                let expiry = crl.next_update().ok_or(Invalid::Evidence)?.timestamp();
                if !trailing.is_empty() || crl.last_update().timestamp() > now || expiry <= now {
                    return Err(Invalid::Evidence);
                }
                until = until.min(expiry);
                crls.push(CertificateRevocationListDer::from(bytes));
            }
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
            until = ocsp::validate(&ders, &self.anchors, files, *max_age_s, now)?;
        }
        Ok(Verdict {
            certificate_end: cert_end,
            evidence_end: cert_end.min(until),
        })
    }
}

#[cfg(test)]
mod tests;
