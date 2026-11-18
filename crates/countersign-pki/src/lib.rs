//! Verify bounded, administrator-imported certificate status evidence.
//! Role-specific path and name validation stays with the caller's TLS verifier.
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer};
use serde::Deserialize;
use std::{
    fs::File,
    io::Read,
    num::NonZeroU32,
    path::{Path, PathBuf},
    time::Duration,
};
use x509_parser::prelude::{parse_x509_certificate, parse_x509_crl};
mod ocsp;
pub use ocsp::validate_ocsp;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Invalid {
    #[error("invalid certificate, trust anchor or status evidence")]
    Evidence,
    #[error("certificate revoked")]
    Revoked,
}
pub type Result<T> = std::result::Result<T, Invalid>;

#[derive(Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Revocation {
    Crl {
        files: Vec<PathBuf>,
    },
    Ocsp {
        files: Vec<PathBuf>,
        max_age_s: Option<NonZeroU32>,
    },
}
pub fn read_import(path: &Path) -> Result<Vec<u8>> {
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
/// Parse complete, direct DER CRLs and bound traffic by this snapshot's
/// freshness. The caller must supply these same bytes to its WebPKI verifier
/// to verify issuer signatures and check all non-anchor certificates.
pub fn crls(
    files: &[PathBuf],
    now: i64,
) -> Result<(Vec<CertificateRevocationListDer<'static>>, i64)> {
    if now < 0 || files.is_empty() || files.len() > 32 {
        return Err(Invalid::Evidence);
    }
    let mut until = i64::MAX;
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
    Ok((crls, until))
}
