use super::*;
use der::{
    Decode, Encode,
    asn1::{BitString, GeneralizedTime, OctetString},
};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateRevocationListParams,
    CustomExtension, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    RevokedCertParams,
};
use ring::{digest, rand::SystemRandom, signature};
use std::{fs, num::NonZeroU32};
use tempfile::TempDir;
use time::{Duration as Days, OffsetDateTime};
use x509_ocsp::{
    BasicOcspResponse, CertId, CertStatus, OcspGeneralizedTime, OcspResponse, ResponderId,
    ResponseData, SingleResponse, Version,
};

struct Authorities {
    dir: TempDir,
    ca: Certificate,
    params: CertificateParams,
    key: KeyPair,
    leaf: PublicChain,
    now: i64,
}
impl Authorities {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Validation root");
        let key = KeyPair::generate().unwrap();
        let ca = params.self_signed(&key).unwrap();
        fs::write(dir.path().join("root.pem"), ca.pem()).unwrap();
        let mut client = CertificateParams::default();
        client.serial_number = Some(17.into());
        client.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let leaf = client
            .signed_by(
                &KeyPair::generate().unwrap(),
                &Issuer::from_params(&params, &key),
            )
            .unwrap();
        let leaf = PublicChain::new(vec![leaf.der().to_vec()]).unwrap();
        Self {
            dir,
            params,
            key,
            ca,
            leaf,
            now: OffsetDateTime::now_utc().unix_timestamp(),
        }
    }
    fn validator(&self, revocation: Revocation) -> Validator {
        Validator::new(
            Profile {
                revocation: Some(revocation),
                ..Default::default()
            },
            &self.dir.path().join("root.pem"),
        )
        .unwrap()
    }
    fn crl(&self, revoked: bool, expiry: i64) -> Vec<u8> {
        let now = OffsetDateTime::from_unix_timestamp(self.now).unwrap();
        let data = CertificateRevocationListParams {
            this_update: now - Days::days(1),
            next_update: OffsetDateTime::from_unix_timestamp(expiry).unwrap(),
            crl_number: 1.into(),
            issuing_distribution_point: None,
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
            revoked_certs: if revoked {
                vec![RevokedCertParams {
                    serial_number: 17.into(),
                    revocation_time: now - Days::hours(1),
                    reason_code: None,
                    invalidity_date: None,
                }]
            } else {
                vec![]
            },
        };
        data.signed_by(&Issuer::from_params(&self.params, &self.key))
            .unwrap()
            .der()
            .to_vec()
    }
    fn ocsp(
        &self,
        signer: &KeyPair,
        signer_cert: &Certificate,
        serial: u32,
        status: CertStatus,
        next: Option<i64>,
    ) -> Vec<u8> {
        let time = |t: i64| {
            OcspGeneralizedTime(
                GeneralizedTime::from_unix_duration(Duration::from_secs(t as u64)).unwrap(),
            )
        };
        let (_, issuer) = parse_x509_certificate(self.ca.der()).unwrap();
        let (_, signing_cert) = parse_x509_certificate(signer_cert.der()).unwrap();
        let hash = |alg, data| OctetString::new(digest::digest(alg, data).as_ref()).unwrap();
        let alg = |oid: &str| spki::AlgorithmIdentifierOwned {
            oid: oid.parse().unwrap(),
            parameters: None,
        };
        let id = CertId {
            hash_algorithm: alg("2.16.840.1.101.3.4.2.1"),
            issuer_name_hash: hash(&digest::SHA256, issuer.subject().as_raw()),
            issuer_key_hash: hash(
                &digest::SHA256,
                &issuer.public_key().subject_public_key.data,
            ),
            serial_number: serial.into(),
        };
        let body = ResponseData {
            version: Version::V1,
            responder_id: ResponderId::ByKey(hash(
                &digest::SHA1_FOR_LEGACY_USE_ONLY,
                &signing_cert.public_key().subject_public_key.data,
            )),
            produced_at: time(self.now - 1),
            responses: vec![SingleResponse {
                cert_id: id,
                cert_status: status,
                this_update: time(self.now - 3),
                next_update: next.map(time),
                single_extensions: None,
            }],
            response_extensions: None,
        };
        let rng = SystemRandom::new();
        let pair = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &signer.serialize_der(),
            &rng,
        )
        .unwrap();
        let sig = pair.sign(&rng, &body.to_der().unwrap()).unwrap();
        let response = BasicOcspResponse {
            tbs_response_data: body,
            signature_algorithm: alg("1.2.840.10045.4.3.2"),
            signature: BitString::from_bytes(sig.as_ref()).unwrap(),
            certs: Some(vec![
                x509_cert::Certificate::from_der(signer_cert.der()).unwrap(),
            ]),
        };
        OcspResponse::successful(response)
            .unwrap()
            .to_der()
            .unwrap()
    }
}

#[test]
fn crl_import_rechecks_signed_status_and_caps_lease_at_next_update() {
    let a = Authorities::new();
    let path = a.dir.path().join("list.der");
    let verify = a.validator(Revocation::Crl {
        files: vec![path.clone()],
    });
    let until = a.now + 12;
    fs::write(&path, a.crl(false, until)).unwrap();
    assert_eq!(
        verify
            .verify("u", &a.leaf, a.now as u64 * 1000)
            .unwrap()
            .evidence_end,
        until
    );
    assert!(verify.verify("u", &a.leaf, until as u64 * 1000).is_err());
    fs::write(&path, a.crl(true, until)).unwrap();
    assert!(matches!(
        verify.verify("u", &a.leaf, a.now as u64 * 1000),
        Err(Invalid::Revoked)
    ));
    let mut fake = a.crl(false, until);
    *fake.last_mut().unwrap() ^= 1;
    fs::write(&path, fake).unwrap();
    assert!(verify.verify("u", &a.leaf, a.now as u64 * 1000).is_err());
}
#[test]
fn ocsp_checks_issuer_cert_id_delegation_and_signed_time_limits() {
    let a = Authorities::new();
    let path = a.dir.path().join("status.der");
    let files = vec![path.clone()];
    let strict = a.validator(Revocation::Ocsp {
        files: files.clone(),
        max_age_s: None,
    });
    let verify = || strict.verify("u", &a.leaf, a.now as u64 * 1000);
    let end = a.now + 50;
    fs::write(
        &path,
        a.ocsp(&a.key, &a.ca, 17, CertStatus::good(), Some(end)),
    )
    .unwrap();
    assert_eq!(verify().unwrap().evidence_end, end);
    for (serial, status, next) in [
        (9, CertStatus::good(), Some(end)),
        (17, CertStatus::unknown(), Some(end)),
        (17, CertStatus::good(), Some(a.now)),
        (17, CertStatus::good(), None),
    ] {
        fs::write(&path, a.ocsp(&a.key, &a.ca, serial, status, next)).unwrap();
        assert!(verify().is_err());
    }
    let bounded = a.validator(Revocation::Ocsp {
        files,
        max_age_s: NonZeroU32::new(10),
    });
    assert_eq!(
        bounded
            .verify("u", &a.leaf, a.now as u64 * 1000)
            .unwrap()
            .evidence_end,
        a.now + 7
    );
    let mut p = CertificateParams::default();
    p.distinguished_name
        .push(rcgen::DnType::CommonName, "Test OCSP responder");
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.custom_extensions.push(CustomExtension::from_oid_content(
        &[1, 3, 6, 1, 5, 5, 7, 48, 1, 5],
        vec![5, 0],
    ));
    let delegate = KeyPair::generate().unwrap();
    for required in [false, true] {
        if required {
            p.extended_key_usages = vec![ExtendedKeyUsagePurpose::OcspSigning];
        }
        let cert = p
            .signed_by(&delegate, &Issuer::from_params(&a.params, &a.key))
            .unwrap();
        fs::write(
            &path,
            a.ocsp(&delegate, &cert, 17, CertStatus::good(), Some(end)),
        )
        .unwrap();
        assert_eq!(verify().is_ok(), required);
        fs::write(
            &path,
            a.ocsp(&a.key, &cert, 17, CertStatus::good(), Some(end)),
        )
        .unwrap();
        assert!(verify().is_err());
    }
}
