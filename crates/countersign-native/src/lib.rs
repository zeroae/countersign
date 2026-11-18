//! Electron-main-only native operations. Provider entry points are private to this crate.
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use countersign_protocol::{Origin, wire::*};
use napi_derive::napi;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Semaphore;
use x509_parser::{prelude::*, public_key::PublicKey};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as platform;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows as platform;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as platform;

type NativeResult<T> = std::result::Result<T, String>;

fn clock_ms() -> NativeResult<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock unavailable")?
        .as_millis() as u64)
}
fn random_id() -> NativeResult<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| "random generator unavailable")?;
    Ok(hex::encode(bytes))
}
fn new_locator(origin: &Origin) -> NativeResult<String> {
    Ok(format!(
        "cs1-{}-{}",
        hex::encode(Sha256::digest(origin.to_string().as_bytes())),
        random_id()?
    ))
}
fn valid_locator(s: &str) -> bool {
    let mut p = s.split('-');
    p.next() == Some("cs1")
        && [64, 32].iter().all(|len| {
            p.next()
                .is_some_and(|s| s.len() == *len && s.bytes().all(|b| b.is_ascii_hexdigit()))
        })
        && p.next().is_none()
}

// A blocked provider dialog retains the execution permit after its caller cancels.
static PROVIDER: Semaphore = Semaphore::const_new(1);
static CAPACITY: Semaphore = Semaphore::const_new(17);

async fn native<F, T>(f: F) -> napi::Result<T>
where
    F: FnOnce() -> NativeResult<T> + Send + 'static,
    T: Send + 'static,
{
    let slot = CAPACITY
        .try_acquire()
        .map_err(|_| napi::Error::from_reason("native queue full"))?;
    let permit = PROVIDER
        .acquire()
        .await
        .map_err(|_| napi::Error::from_reason("native provider unavailable"))?;
    tokio::task::spawn_blocking(move || {
        let _held = (permit, slot);
        f()
    })
    .await
    .map_err(|_| napi::Error::from_reason("native provider failed"))?
    .map_err(napi::Error::from_reason)
}

#[napi]
pub fn validate_broker_frame(text: String) -> napi::Result<String> {
    let frame = Frame::<BrokerToCompanion>::decode(text.as_bytes())
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    let bytes = frame
        .encode()
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    String::from_utf8(bytes).map_err(|_| napi::Error::from_reason("invalid frame encoding"))
}

#[napi]
pub async fn create_pairing_key(integrator_origin: String) -> napi::Result<Value> {
    native(move || {
        let origin = Origin::parse(&integrator_origin).map_err(|e| e.to_string())?;
        let locator = new_locator(&origin)?;
        let public = platform::create_pairing(&locator)?;
        Ok(json!({"locator":locator,"publicSec1":STANDARD.encode(public)}))
    })
    .await
}

#[napi]
pub async fn pairing_public_key(locator: String) -> napi::Result<String> {
    native(move || {
        if !valid_locator(&locator) {
            return Err("invalid pairing locator".into());
        }
        Ok(STANDARD.encode(platform::pairing_public(&locator)?))
    })
    .await
}

#[napi]
pub async fn prove_pairing(
    locator: String,
    challenge_json: String,
    integrator_origin: String,
) -> napi::Result<String> {
    native(move || {
        if challenge_json.len() > 16_384 || !valid_locator(&locator) {
            return Err("invalid device proof request".into());
        }
        let c: Challenge =
            serde_json::from_str(&challenge_json).map_err(|_| "invalid challenge")?;
        let origin = Origin::parse(&integrator_origin).map_err(|e| e.to_string())?;
        let prefix = format!(
            "cs1-{}-",
            hex::encode(Sha256::digest(origin.to_string().as_bytes()))
        );
        let now = clock_ms()?;
        if origin != c.integrator_origin
            || origin != c.broker_origin
            || !locator.starts_with(&prefix)
            || now < c.issued_at_ms
            || now >= c.expires_at_ms
            || c.expires_at_ms.saturating_sub(c.issued_at_ms) > 60_000
        {
            return Err("challenge authority or deadline mismatch".into());
        }
        let public = platform::pairing_public(&locator)?;
        if URL_SAFE_NO_PAD.encode(Sha256::digest(public)) != c.key.as_str() {
            return Err("challenge key mismatch".into());
        }
        let header =
            URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","typ":"countersign-device-proof+jws"}"#);
        let claims =
            serde_json::to_vec(&json!({"version":1,"challenge":c})).map_err(|_| "encode proof")?;
        let signed = format!("{header}.{}", URL_SAFE_NO_PAD.encode(claims));
        let raw = platform::pairing_sign(&locator, signed.as_bytes())?;
        let sig =
            p256::ecdsa::Signature::from_slice(&raw).map_err(|_| "invalid device signature")?;
        Ok(format!(
            "{signed}.{}",
            URL_SAFE_NO_PAD.encode(sig.to_bytes())
        ))
    })
    .await
}

#[napi]
pub async fn retire_pairing_key(locator: String) -> napi::Result<()> {
    native(move || {
        if !valid_locator(&locator) {
            return Err("invalid pairing locator".into());
        }
        platform::retire_pairing(&locator)
    })
    .await
}

pub(crate) struct Identity {
    chain: Vec<Vec<u8>>,
    // Provider-private locator for this identity. Never sent to JS or the Broker.
    key: Vec<u8>,
}

struct Selection {
    identity: Identity,
    fingerprint: Fingerprint,
    expires: Instant,
}
struct Active {
    binding: GrantBinding,
    selected: Arc<Selection>,
    expires_at_ms: u64,
    expires: Instant,
    used: HashMap<String, u64>,
}
type GrantKey = (Id, Id);
fn grant_key(binding: &GrantBinding) -> GrantKey {
    (binding.device.key.clone(), binding.grant.clone())
}
type OperationKey = (GrantKey, Id);
fn operation_key(op: &Operation) -> OperationKey {
    (grant_key(&op.grant), op.operation.clone())
}

#[derive(Default)]
struct State {
    selections: HashMap<String, Arc<Selection>>,
    active: HashMap<GrantKey, Active>,
    pending: HashMap<OperationKey, (Operation, bool)>,
}
static STATE: LazyLock<Mutex<State>> = LazyLock::new(|| Mutex::new(State::default()));

fn eligible(der: &[u8]) -> NativeResult<(String, String, i64)> {
    let (remaining, c) = X509Certificate::from_der(der).map_err(|_| "unreadable certificate")?;
    if !remaining.is_empty()
        || !c.validity().is_valid()
        || c.is_ca()
        || c.key_usage()
            .map_err(|_| "invalid KU")?
            .is_some_and(|u| !u.value.digital_signature())
        || c.extended_key_usage()
            .map_err(|_| "invalid EKU")?
            .is_some_and(|u| !u.value.client_auth && !u.value.any)
    {
        return Err("ineligible certificate".into());
    }
    if supported_schemes(&c)?.is_empty() {
        return Err("ineligible key".into());
    }
    Ok((
        c.subject().to_string(),
        c.issuer().to_string(),
        c.validity().not_after.timestamp() * 1000,
    ))
}

fn supported_schemes(leaf: &X509Certificate<'_>) -> NativeResult<&'static [SignatureScheme]> {
    use SignatureScheme::*;
    match leaf.public_key().parsed().map_err(|_| "ineligible key")? {
        PublicKey::RSA(key) if (2048..=8192).contains(&key.key_size()) => Ok(&[
            RsaPssSha256,
            RsaPssSha384,
            RsaPssSha512,
            RsaPkcs1Sha256,
            RsaPkcs1Sha384,
            RsaPkcs1Sha512,
        ]),
        PublicKey::EC(_) => {
            let curve = leaf
                .public_key()
                .algorithm
                .parameters
                .as_ref()
                .and_then(|param| param.as_oid().ok())
                .map(|oid| oid.to_id_string());
            Ok(match curve.as_deref() {
                Some("1.2.840.10045.3.1.7") => &[EcdsaNistp256Sha256],
                Some("1.3.132.0.34") => &[EcdsaNistp384Sha384],
                _ => &[],
            })
        }
        _ => Ok(&[]),
    }
}

fn matches_hints(hints: &IdentityHints, chain: &[Vec<u8>], fingerprint: &Fingerprint) -> bool {
    if hints
        .cert_fingerprints
        .as_ref()
        .is_some_and(|allowed| !allowed.contains(fingerprint))
    {
        return false;
    }
    if !hints.signature_schemes.is_empty() {
        let Some((_, leaf)) = chain
            .first()
            .and_then(|der| X509Certificate::from_der(der).ok())
        else {
            return false;
        };
        if !supported_schemes(&leaf)
            .is_ok_and(|schemes| schemes.iter().any(|s| hints.signature_schemes.contains(s)))
        {
            return false;
        }
    }
    hints.issuer_names.is_empty()
        || chain.iter().any(|der| {
            X509Certificate::from_der(der).is_ok_and(|(_, cert)| {
                hints
                    .issuer_names
                    .iter()
                    .any(|name| name.as_slice() == cert.issuer().as_raw())
            })
        })
}

#[napi]
pub async fn list_identities(hints_json: Option<String>) -> napi::Result<Vec<Value>> {
    native(move || {
        let hints: IdentityHints = match hints_json {
            None => IdentityHints::default(),
            Some(json) if json.len() <= MAX_FRAME_BYTES => {
                serde_json::from_str(&json).map_err(|_| "invalid identity constraints")?
            }
            _ => return Err("oversized identity constraints".into()),
        };
        let identities = platform::identities()?;
        let mut choices = Vec::new();
        let mut st = STATE.lock().map_err(|_| "state unavailable")?;
        st.selections.retain(|_, s| s.expires > Instant::now());
        for identity in identities {
            let Some(leaf) = identity.chain.first() else {
                continue;
            };
            let Ok((subject, issuer, expires_at_ms)) = eligible(leaf) else {
                continue;
            };
            let cert_sha256 = Fingerprint::new(Sha256::digest(leaf).into());
            if !matches_hints(&hints, &identity.chain, &cert_sha256) {
                continue;
            }
            let Ok(chain) = PublicChain::new(identity.chain.clone()) else {
                continue;
            };
            if st.selections.len() >= 4096 {
                return Err("identity selection limit reached".into());
            }
            let selection = random_id()?;
            choices.push(json!({
                "selection": selection, "subject": subject, "issuer": issuer,
                "expiresAtMs": expires_at_ms, "certSha256": cert_sha256, "chain": chain,
            }));
            st.selections.insert(
                selection,
                Arc::new(Selection {
                    identity,
                    fingerprint: cert_sha256,
                    expires: Instant::now() + Duration::from_secs(600),
                }),
            );
        }
        Ok(choices)
    })
    .await
}

#[napi]
pub fn activate_scope(activation_json: String, selection: String) -> napi::Result<()> {
    if activation_json.len() > MAX_FRAME_BYTES {
        return Err(napi::Error::from_reason("invalid scope"));
    }
    let activation: Activate = serde_json::from_str(&activation_json)
        .map_err(|_| napi::Error::from_reason("invalid scope"))?;
    let mut st = STATE
        .lock()
        .map_err(|_| napi::Error::from_reason("state unavailable"))?;
    let selected = st
        .selections
        .remove(&selection)
        .ok_or_else(|| napi::Error::from_reason("selection expired"))?;
    let now = clock_ms().map_err(napi::Error::from_reason)?;
    let (_, _, expires) =
        eligible(&selected.identity.chain[0]).map_err(napi::Error::from_reason)?;
    if selected.expires <= Instant::now()
        || activation.expires_at_ms <= now
        || activation.expires_at_ms > expires as u64
        || activation.grant.cert_sha256 != selected.fingerprint
    {
        return Err(napi::Error::from_reason("selection or grant mismatch"));
    }
    let started = Instant::now();
    let expires = started
        .checked_add(Duration::from_millis(activation.expires_at_ms - now))
        .ok_or_else(|| napi::Error::from_reason("invalid grant lifetime"))?;
    st.active
        .retain(|_, a| a.expires_at_ms > now && a.expires > started);
    if st.active.contains_key(&grant_key(&activation.grant)) || st.active.len() >= 256 {
        return Err(napi::Error::from_reason("grant slot unavailable"));
    }
    st.active.insert(
        grant_key(&activation.grant),
        Active {
            binding: activation.grant,
            selected,
            expires_at_ms: activation.expires_at_ms,
            expires,
            used: HashMap::new(),
        },
    );
    Ok(())
}

#[napi]
pub fn retire_scope(binding_json: String) -> napi::Result<()> {
    if binding_json.len() > MAX_FRAME_BYTES {
        return Err(napi::Error::from_reason("invalid retirement"));
    }
    let binding: GrantBinding = serde_json::from_str(&binding_json)
        .map_err(|_| napi::Error::from_reason("invalid retirement"))?;
    let key = grant_key(&binding);
    let mut st = STATE
        .lock()
        .map_err(|_| napi::Error::from_reason("state unavailable"))?;
    if st.active.get(&key).is_some_and(|a| a.binding == binding) {
        st.active.remove(&key);
    }
    for (grant, cancelled) in st.pending.values_mut() {
        if grant.grant == binding {
            *cancelled = true
        }
    }
    Ok(())
}
#[napi]
pub fn cancel_operation(operation_json: String) -> napi::Result<()> {
    if operation_json.len() > MAX_FRAME_BYTES {
        return Err(napi::Error::from_reason("invalid cancellation"));
    }
    let op: Operation = serde_json::from_str(&operation_json)
        .map_err(|_| napi::Error::from_reason("invalid cancellation"))?;
    if let Some((binding, cancelled)) = STATE
        .lock()
        .map_err(|_| napi::Error::from_reason("state unavailable"))?
        .pending
        .get_mut(&operation_key(&op))
        && *binding == op
    {
        *cancelled = true
    }
    Ok(())
}

#[napi]
pub async fn sign_tls(sign_json: String) -> napi::Result<String> {
    if sign_json.len() > MAX_FRAME_BYTES {
        return Err(napi::Error::from_reason("oversized signing operation"));
    }
    let request: Sign = serde_json::from_str(&sign_json)
        .map_err(|_| napi::Error::from_reason("invalid signing operation"))?;
    let operation = operation_key(&request.binding);
    let grant = grant_key(&request.binding.grant);
    let now = clock_ms().map_err(napi::Error::from_reason)?;
    let selection = {
        let mut st = STATE
            .lock()
            .map_err(|_| napi::Error::from_reason("state unavailable"))?;
        if st.pending.contains_key(&operation)
            || st.pending.keys().filter(|(g, _)| g == &grant).count() >= 4
        {
            return Err(napi::Error::from_reason("operation busy"));
        }
        let active = st
            .active
            .get_mut(&grant)
            .ok_or_else(|| napi::Error::from_reason("inactive grant"))?;
        if active.expires <= Instant::now()
            || request.binding.grant != active.binding
            || !active
                .binding
                .scope
                .pattern()
                .matches(&request.binding.host)
            || request.deadline_ms <= now
            || request.deadline_ms > active.expires_at_ms
            || request.deadline_ms - now > 120_000
        {
            return Err(napi::Error::from_reason("operation outside active grant"));
        }
        active.used.retain(|_, expiry| *expiry > now);
        if active.used.len() >= 4096 || active.used.contains_key(operation.1.as_str()) {
            return Err(napi::Error::from_reason("reused or full operation slot"));
        }
        active
            .used
            .insert(operation.1.as_str().to_string(), request.deadline_ms);
        let selection = active.selected.clone();
        st.pending
            .insert(operation.clone(), (request.binding.clone(), false));
        selection
    };
    let key = operation.clone();
    let result = native(move || {
        ensure_current(&key, request.deadline_ms)?;
        let cert = &selection.identity.chain[0];
        eligible(cert)?;
        let (_, leaf) = X509Certificate::from_der(cert).map_err(|_| "invalid selected leaf")?;
        if !supported_schemes(&leaf)?.contains(&request.scheme) {
            return Err("scheme incompatible with selected key".into());
        }
        check_transcript(&request, cert)?;
        let signature = platform::sign_identity(
            &selection.identity,
            request.scheme,
            request.certificate_verify.as_slice(),
        )?;
        ensure_current(&key, request.deadline_ms)?;
        Ok(STANDARD.encode(signature))
    })
    .await;
    STATE
        .lock()
        .map_err(|_| napi::Error::from_reason("state unavailable"))?
        .pending
        .remove(&operation);
    result
}
fn ensure_current(op: &OperationKey, deadline: u64) -> NativeResult<()> {
    let state = STATE.lock().map_err(|_| "state unavailable")?;
    if !state
        .pending
        .get(op)
        .is_some_and(|(_, cancelled)| !*cancelled)
        || !state
            .active
            .get(&op.0)
            .is_some_and(|grant| grant.expires > Instant::now())
        || clock_ms()? >= deadline
    {
        return Err("operation cancelled or expired".into());
    }
    Ok(())
}
/// Read a TLS vector with a 1- or 2-byte length prefix.
fn vector<'a>(input: &mut &'a [u8], width: usize) -> Option<&'a [u8]> {
    let n = match width {
        1 => *input.first()? as usize,
        2 => u16::from_be_bytes(input.get(..2)?.try_into().ok()?) as usize,
        _ => return None,
    };
    let value = input.get(width..width + n)?;
    *input = &input[width + n..];
    Some(value)
}

fn tls12_sni(hello: &[u8]) -> Option<&[u8]> {
    // legacy_version, random, session_id, cipher_suites, compression_methods.
    let mut bytes = hello.get(34..)?;
    vector(&mut bytes, 1)?;
    vector(&mut bytes, 2)?;
    vector(&mut bytes, 1)?;
    let mut extensions = vector(&mut bytes, 2)?;
    if !bytes.is_empty() {
        return None;
    }
    let mut sni = None;
    while !extensions.is_empty() {
        let typ = extensions.get(..2)?;
        extensions = &extensions[2..];
        let mut data = vector(&mut extensions, 2)?;
        if typ != [0, 0] {
            continue;
        }
        let mut names = vector(&mut data, 2)?;
        if !data.is_empty() || sni.is_some() || names.first()? != &0 {
            return None;
        }
        names = &names[1..];
        sni = Some(vector(&mut names, 2)?);
        if !names.is_empty() {
            return None;
        }
    }
    sni
}

fn check_transcript(req: &Sign, leaf: &[u8]) -> NativeResult<()> {
    let bytes = req.certificate_verify.as_slice();
    match req.tls {
        TlsVersion::Tls13 => {
            let prefix = [&[0x20u8; 64][..], b"TLS 1.3, client CertificateVerify\0"].concat();
            if !bytes
                .strip_prefix(&prefix[..])
                .is_some_and(|hash| matches!(hash.len(), 32 | 48))
                || matches!(
                    req.scheme,
                    SignatureScheme::RsaPkcs1Sha256
                        | SignatureScheme::RsaPkcs1Sha384
                        | SignatureScheme::RsaPkcs1Sha512
                )
            {
                return Err("invalid TLS 1.3 CertificateVerify input".into());
            }
        }
        TlsVersion::Tls12 => {
            let mut rest = bytes;
            let mut types = Vec::new();
            while !rest.is_empty() {
                let header = rest.get(..4).ok_or("invalid TLS transcript")?;
                let n = u32::from_be_bytes([0, header[1], header[2], header[3]]) as usize;
                let body = rest.get(4..4 + n).ok_or("truncated TLS transcript")?;
                if types.len() == 9 {
                    return Err("excess TLS transcript messages".into());
                }
                if header[0] == 1 && tls12_sni(body) != Some(req.binding.host.host().as_bytes()) {
                    return Err("TLS ClientHello has a different origin".into());
                }
                if header[0] == 11 && types.contains(&14) {
                    // TLS 1.2 Certificate after ServerHelloDone is the client chain.
                    let list = body.get(..3).ok_or("missing client chain")?;
                    let length = u32::from_be_bytes([0, list[0], list[1], list[2]]) as usize;
                    let first = body.get(3..6).ok_or("missing selected leaf")?;
                    let leaf_length =
                        u32::from_be_bytes([0, first[0], first[1], first[2]]) as usize;
                    if body.len() != 3 + length || body.get(6..6 + leaf_length) != Some(leaf) {
                        return Err("TLS transcript has a different client identity".into());
                    }
                }
                types.push(header[0]);
                rest = &rest[4 + n..];
            }
            if types.as_slice() != [1, 2, 11, 12, 13, 14, 11, 16]
                && types.as_slice() != [1, 2, 11, 22, 12, 13, 14, 11, 16]
            {
                return Err("unsupported TLS 1.2 client authentication transcript".into());
            }
        }
    }
    Ok(())
}
