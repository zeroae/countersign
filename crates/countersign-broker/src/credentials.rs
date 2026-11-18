//! Authentication for Integrator backends and short-lived Workload credentials.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use countersign_protocol::wire::{Challenge, WorkloadBinding};
use ring::{digest, hmac, signature};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JwsHeader {
    alg: String,
    typ: String,
}

fn split_jws(token: &str) -> Option<(&str, JwsHeader, Vec<u8>, Vec<u8>)> {
    if token.len() > 16_384 {
        return None;
    }
    let (signing_input, encoded_sig) = token.rsplit_once('.')?;
    let (header, claims) = signing_input.split_once('.')?;
    let header = serde_json::from_slice(&B64.decode(header).ok()?).ok()?;
    Some((
        signing_input,
        header,
        B64.decode(claims).ok()?,
        B64.decode(encoded_sig).ok()?,
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofClaims {
    version: u16,
    challenge: Challenge,
}

pub(crate) fn verify_device_proof(
    key: &[u8],
    challenge: &Challenge,
    proof: &str,
    now: u64,
) -> bool {
    if now < challenge.issued_at_ms || now >= challenge.expires_at_ms {
        return false;
    }
    let Some((input, header, body, sig)) = split_jws(proof) else {
        return false;
    };
    if header.typ != "countersign-device-proof+jws" || header.alg != "ES256" {
        return false;
    }
    let Ok(claims) = serde_json::from_slice::<ProofClaims>(&body) else {
        return false;
    };
    if claims.version != 1
        || serde_json::to_vec(&claims.challenge).ok() != serde_json::to_vec(challenge).ok()
    {
        return false;
    }
    signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, key)
        .verify(input.as_bytes(), &sig)
        .is_ok()
}

/// Stores a keyed tag so comparisons of supplied backend credentials are
/// constant-time and the secret's contents are never retained in debug output.
pub(crate) struct Credentials {
    signing_key: hmac::Key,
    backend_tag: hmac::Tag,
    admin_tag: Option<hmac::Tag>,
    gateway_tag: Option<hmac::Tag>,
    issuer: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Claims {
    iss: String,
    aud: String,
    scope: String,
    jti: String,
    iat: u64,
    exp: u64,
    binding: WorkloadBinding,
}

const AUD: &str = "countersign:broker:workload";
impl Credentials {
    pub(crate) fn new(
        key: &[u8],
        backend: &[u8],
        gateway: Option<&str>,
        admin: Option<&str>,
        issuer: String,
    ) -> Option<Self> {
        if key.len() < 32 || backend.len() < 32 || key == backend {
            return None;
        }
        // Each reference Broker boot starts a new authority epoch. A token
        // recovered from a prior process cannot authorize new traffic.
        let root = hmac::Key::new(hmac::HMAC_SHA256, key);
        let epoch_key = hmac::sign(&root, Uuid::new_v4().as_bytes());
        let signing_key = hmac::Key::new(hmac::HMAC_SHA256, epoch_key.as_ref());
        let backend_tag = hmac::sign(&signing_key, backend);
        if gateway.is_some_and(|g| g.len() < 32 || g.as_bytes() == key || g.as_bytes() == backend) {
            return None;
        }
        if admin.is_some_and(|a| {
            a.len() < 32 || Some(a) == gateway || a.as_bytes() == key || a.as_bytes() == backend
        }) {
            return None;
        }
        let admin_tag = admin.map(|a| hmac::sign(&signing_key, a.as_bytes()));
        let gateway_tag = gateway.map(|g| hmac::sign(&signing_key, g.as_bytes()));
        Some(Self {
            signing_key,
            backend_tag,
            admin_tag,
            gateway_tag,
            issuer,
        })
    }
    pub(crate) fn backend_authorized(&self, candidate: &[u8]) -> bool {
        hmac::verify(&self.signing_key, candidate, self.backend_tag.as_ref()).is_ok()
    }
    pub(crate) fn admin_authorized(&self, candidate: &[u8]) -> bool {
        self.admin_tag
            .as_ref()
            .is_some_and(|tag| hmac::verify(&self.signing_key, candidate, tag.as_ref()).is_ok())
    }
    pub(crate) fn issue(
        &self,
        binding: WorkloadBinding,
        now: u64,
        shared: bool,
    ) -> Option<(String, u64)> {
        let exp = now.checked_add(120)?;
        if shared && self.gateway_tag.is_none() {
            return None;
        }
        let claims = Claims {
            iss: self.issuer.clone(),
            aud: if shared {
                "countersign:gateway:workload"
            } else {
                AUD
            }
            .into(),
            scope: "proxy".into(),
            jti: Uuid::new_v4().to_string(),
            iat: now,
            exp,
            binding,
        };
        let payload = B64.encode(serde_json::to_vec(&claims).ok()?);
        let header = B64.encode(br#"{"alg":"HS256","typ":"countersign-workload+jwt"}"#);
        let input = format!("{header}.{payload}");
        let tag = hmac::sign(&self.signing_key, input.as_bytes());
        Some((format!("{input}.{}", B64.encode(tag)), exp))
    }
    pub(crate) fn workload(
        &self,
        token: &str,
        now: u64,
        gateway: Option<&str>,
    ) -> Option<(WorkloadBinding, u64)> {
        let (input, header, body, sig) = split_jws(token)?;
        if header.typ != "countersign-workload+jwt" || header.alg != "HS256" {
            return None;
        }
        hmac::verify(&self.signing_key, input.as_bytes(), &sig).ok()?;
        let claims: Claims = serde_json::from_slice(&body).ok()?;
        if claims.iss != self.issuer
            || (claims.aud != AUD
                && !(claims.aud == "countersign:gateway:workload"
                    && self
                        .gateway_tag
                        .as_ref()
                        .zip(gateway)
                        .is_some_and(|(tag, g)| {
                            hmac::verify(&self.signing_key, g.as_bytes(), tag.as_ref()).is_ok()
                        })))
            || claims.scope != "proxy"
            || claims.iat > now
            || claims.exp <= now
            || claims.exp.saturating_sub(claims.iat) > 120
        {
            return None;
        }
        Some((claims.binding, claims.exp))
    }
}

pub(crate) fn fingerprint(data: &[u8]) -> [u8; 32] {
    digest::digest(&digest::SHA256, data)
        .as_ref()
        .try_into()
        .expect("SHA-256 size")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn workload_audience_expiry_and_restart_epoch_are_enforced() {
        let service = || {
            Credentials::new(
                &[0xa5; 32],
                &[0x5a; 32],
                Some("shared-gateway-dedicated-test-credential"),
                Some("administrator-dedicated-test-credential"),
                "integrator".into(),
            )
            .unwrap()
        };
        let creds = service();
        let workload = serde_json::from_value(json!({
            "integrator":"integrator","user":"u","context":"c","workload":"w","workload_generation":1
        })).unwrap();
        let (shared, end) = creds.issue(workload, 100, true).unwrap();
        let service_secret = "shared-gateway-dedicated-test-credential";
        assert!(creds.workload(&shared, 100, None).is_none());
        assert!(creds.workload(&shared, 100, Some("other")).is_none());
        let (binding, _) = creds.workload(&shared, 100, Some(service_secret)).unwrap();
        assert!(creds.workload(&shared, end, Some(service_secret)).is_none());
        assert!(creds.workload(&shared, 99, Some(service_secret)).is_none());
        assert!(
            service()
                .workload(&shared, 100, Some(service_secret))
                .is_none()
        );
        let (sidecar, _) = creds.issue(binding, 100, false).unwrap();
        assert!(creds.workload(&sidecar, 100, None).is_some());
        let body = shared.split('.').nth(1).unwrap();
        let (head, _) = sidecar.split_once('.').unwrap();
        let (_, sig) = sidecar.rsplit_once('.').unwrap();
        assert!(
            creds
                .workload(&format!("{head}.{body}.{sig}"), 100, Some(service_secret))
                .is_none()
        );
        assert!(!creds.backend_authorized(service_secret.as_bytes()));
        assert!(!creds.admin_authorized(&[0x5a; 32]));
    }
}
