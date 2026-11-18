use super::*;
use der::{Decode, Encode, asn1::AnyRef};
use ring::digest;
use rustls::pki_types::UnixTime;
use webpki::EndEntityCert;
use x509_ocsp::{BasicOcspResponse, CertStatus, OcspResponse, OcspResponseStatus, ResponderId};
use x509_parser::certificate::X509Certificate;

/// Verify imported OCSP status for each non-anchor certificate in a chain
/// already authenticated for its application role. Returns the earliest expiry.
pub fn validate_ocsp(
    ders: &[CertificateDer<'_>],
    roots: &[CertificateDer<'_>],
    files: &[PathBuf],
    age: Option<NonZeroU32>,
    now: i64,
) -> Result<i64> {
    // This import profile accepts an ordered chain. Verify the issuer
    // relationship for each link independently of webpki's path selection.
    if now < 0
        || ders.is_empty()
        || roots.is_empty()
        || files.is_empty()
        || files.len() > 32
        || roots.iter().any(|r| r.as_ref() == ders[0].as_ref())
    {
        return Err(Invalid::Evidence);
    }
    let mut responses = Vec::new();
    for path in files {
        let outer = OcspResponse::from_der(&read_import(path)?).map_err(|_| Invalid::Evidence)?;
        let bytes = outer.response_bytes.ok_or(Invalid::Evidence)?;
        if outer.response_status != OcspResponseStatus::Successful
            || bytes.response_type.to_string() != "1.3.6.1.5.5.7.48.1.1"
        {
            return Err(Invalid::Evidence);
        }
        responses.push(
            BasicOcspResponse::from_der(bytes.response.as_bytes())
                .map_err(|_| Invalid::Evidence)?,
        );
    }
    let mut end = i64::MAX;
    for (i, subject_der) in ders.iter().enumerate() {
        if roots.iter().any(|r| r.as_ref() == subject_der.as_ref()) {
            if i + 1 != ders.len() {
                return Err(Invalid::Evidence);
            }
            break;
        }
        let (_, subject) =
            parse_x509_certificate(subject_der.as_ref()).map_err(|_| Invalid::Evidence)?;
        let issuer_der = match ders.get(i + 1) {
            Some(next) => next,
            None => roots
                .iter()
                .find(|root| {
                    parse_x509_certificate(root.as_ref())
                        .is_ok_and(|(_, issuer)| issued(&subject, &issuer))
                })
                .ok_or(Invalid::Evidence)?,
        };
        let (_, issuer) =
            parse_x509_certificate(issuer_der.as_ref()).map_err(|_| Invalid::Evidence)?;
        if !issued(&subject, &issuer) {
            return Err(Invalid::Evidence);
        }
        let mut verified = None;
        for basic in &responses {
            let tbs = &basic.tbs_response_data;
            for r in &tbs.responses {
                let id = &r.cert_id;
                let hash = match id.hash_algorithm.oid.to_string().as_str() {
                    "1.3.14.3.2.26" => &digest::SHA1_FOR_LEGACY_USE_ONLY,
                    "2.16.840.1.101.3.4.2.1" => &digest::SHA256,
                    _ => return Err(Invalid::Evidence),
                };
                if id.issuer_name_hash.as_bytes()
                    != digest::digest(hash, issuer.subject().as_raw()).as_ref()
                    || id.issuer_key_hash.as_bytes()
                        != digest::digest(
                            hash,
                            issuer.public_key().subject_public_key.data.as_ref(),
                        )
                        .as_ref()
                    || id
                        .serial_number
                        .as_bytes()
                        .strip_prefix(&[0])
                        .unwrap_or(id.serial_number.as_bytes())
                        != subject
                            .raw_serial()
                            .strip_prefix(&[0])
                            .unwrap_or(subject.raw_serial())
                {
                    continue;
                }
                if verified.is_some()
                    || r.single_extensions
                        .as_ref()
                        .is_some_and(|v| v.iter().any(|e| e.critical))
                    || tbs
                        .response_extensions
                        .as_ref()
                        .is_some_and(|v| v.iter().any(|e| e.critical))
                {
                    return Err(Invalid::Evidence);
                }
                let produced = tbs.produced_at.0.to_unix_duration().as_secs() as i64;
                let this = r.this_update.0.to_unix_duration().as_secs() as i64;
                let max = age.map(|s| this + s.get() as i64);
                let next = r
                    .next_update
                    .map(|t| t.0.to_unix_duration().as_secs() as i64)
                    .or(max)
                    .ok_or(Invalid::Evidence)?;
                let until = next.min(max.unwrap_or(i64::MAX));
                if this > produced || produced > now || until <= now {
                    return Err(Invalid::Evidence);
                }
                let responder_end = verify_response(basic, issuer_der, now, produced)?;
                match r.cert_status {
                    CertStatus::Good(_) => {}
                    CertStatus::Revoked(_) => return Err(Invalid::Revoked),
                    _ => return Err(Invalid::Evidence),
                }
                verified = Some(until.min(responder_end));
            }
        }
        end = end.min(verified.ok_or(Invalid::Evidence)?);
    }
    Ok(end)
}

fn issued(child: &X509Certificate<'_>, issuer: &X509Certificate<'_>) -> bool {
    child.issuer() == issuer.subject() && child.verify_signature(Some(issuer.public_key())).is_ok()
}

fn verify_response(
    basic: &BasicOcspResponse,
    issuer_der: &CertificateDer<'_>,
    now: i64,
    produced: i64,
) -> Result<i64> {
    let mut responders = vec![issuer_der.clone()];
    for cert in basic.certs.as_deref().unwrap_or(&[]) {
        responders.push(CertificateDer::from(
            cert.to_der().map_err(|_| Invalid::Evidence)?,
        ));
    }
    let alg = basic
        .signature_algorithm
        .to_der()
        .map_err(|_| Invalid::Evidence)?;
    let alg = AnyRef::from_der(&alg)
        .map_err(|_| Invalid::Evidence)?
        .value();
    let body = basic
        .tbs_response_data
        .to_der()
        .map_err(|_| Invalid::Evidence)?;
    let sig = basic.signature.as_bytes().ok_or(Invalid::Evidence)?;
    let provider = rustls::crypto::ring::default_provider();
    let algorithms = provider.signature_verification_algorithms.all;
    for candidate in responders {
        let (_, cert) =
            parse_x509_certificate(candidate.as_ref()).map_err(|_| Invalid::Evidence)?;
        let matches = match &basic.tbs_response_data.responder_id {
            ResponderId::ByName(name) => {
                name.to_der().map_err(|_| Invalid::Evidence)? == cert.subject().as_raw()
            }
            ResponderId::ByKey(hash) => {
                hash.as_bytes()
                    == digest::digest(
                        &digest::SHA1_FOR_LEGACY_USE_ONLY,
                        cert.public_key().subject_public_key.data.as_ref(),
                    )
                    .as_ref()
            }
        };
        if !matches {
            continue;
        }
        let ee = EndEntityCert::try_from(&candidate).map_err(|_| Invalid::Evidence)?;
        if candidate.as_ref() != issuer_der.as_ref() {
            // Delegate must chain directly to this issuer, have the explicit
            // OCSPSigning EKU and be permitted to sign at this time. Require
            // id-pkix-ocsp-nocheck for this offline import profile.
            if !cert
                .extensions()
                .iter()
                .any(|e| e.oid.to_string() == "1.3.6.1.5.5.7.48.1.5" && e.value == [0x05, 0x00])
            {
                continue;
            }
            let root =
                webpki::anchor_from_trusted_cert(issuer_der).map_err(|_| Invalid::Evidence)?;
            if ee
                .verify_for_usage(
                    algorithms,
                    &[root],
                    &[],
                    UnixTime::since_unix_epoch(Duration::from_secs(now as u64)),
                    webpki::KeyUsage::required(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09]),
                    None,
                    None,
                )
                .is_err()
            {
                continue;
            }
            if cert
                .key_usage()
                .map_err(|_| Invalid::Evidence)?
                .is_some_and(|u| !u.value.digital_signature())
            {
                continue;
            }
        }
        let valid = cert.validity();
        if valid.not_before.timestamp() > produced || valid.not_after.timestamp() <= now {
            continue;
        }
        if algorithms
            .iter()
            .filter(|a| a.signature_alg_id().as_ref() == alg)
            .any(|a| ee.verify_signature(*a, &body, sig).is_ok())
        {
            return Ok(valid.not_after.timestamp());
        }
    }
    Err(Invalid::Evidence)
}
