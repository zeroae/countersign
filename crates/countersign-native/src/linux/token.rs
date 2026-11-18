//! Installed website identities from an administrator-selected PKCS#11 module.
use super::secret;
use crate::{Identity, NativeResult, eligible};
use countersign_protocol::wire::SignatureScheme;
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    error::{Error, RvError},
    mechanism::{
        Mechanism, MechanismType,
        rsa::{PkcsMgfType, PkcsPssParams},
    },
    object::{Attribute, AttributeType, ObjectClass, ObjectHandle},
    session::{Session, UserType},
    slot::Slot,
    types::RawAuthPin,
};
use sha2::{Digest, Sha256, Sha384};
use std::path::PathBuf;
use std::sync::OnceLock;
use x509_parser::prelude::*;

fn module() -> NativeResult<&'static Pkcs11> {
    static MODULE: OnceLock<Pkcs11> = OnceLock::new();
    if let Some(m) = MODULE.get() {
        return Ok(m);
    }
    let path = std::env::var_os("COUNTERSIGN_PKCS11_MODULE").map(PathBuf::from);
    if path.as_ref().is_some_and(|p| !p.is_absolute()) {
        return Err("configure an absolute PKCS#11 module path".into());
    }
    let m = Pkcs11::new(path.unwrap_or_else(|| "p11-kit-proxy.so".into()))
        .map_err(|_| "PKCS#11 module unavailable")?;
    match m.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(()) | Err(Error::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => (),
        Err(_) => return Err("initialize PKCS#11 module".into()),
    }
    let _ = MODULE.set(m);
    MODULE
        .get()
        .ok_or_else(|| "PKCS#11 module unavailable".into())
}
fn session(m: &Pkcs11, slot: Slot) -> NativeResult<Session> {
    let info = m.get_token_info(slot).map_err(|_| "token unavailable")?;
    let session = m
        .open_ro_session(slot)
        .map_err(|_| "token session unavailable")?;
    if info.login_required() {
        let login = if info.protected_authentication_path() {
            session.login(UserType::User, None)
        } else {
            let secret = secret("website-token", "token", info.label())?;
            session.login_with_raw(UserType::User, &RawAuthPin::new(secret.to_vec().into()))
        };
        match login {
            Ok(()) | Err(Error::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => (),
            Err(_) => return Err("native token unlock denied".into()),
        }
    }
    Ok(session)
}
fn private(session: &Session, id: &[u8]) -> NativeResult<ObjectHandle> {
    let keys = session
        .find_objects(&[
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Sign(true),
            Attribute::Id(id.to_vec()),
        ])
        .map_err(|_| "find native key")?;
    match &keys[..] {
        [key] => Ok(*key),
        _ => Err("missing or ambiguous native key".into()),
    }
}
fn certificates(session: &Session) -> NativeResult<Vec<(Vec<u8>, Vec<u8>)>> {
    let certs = session
        .find_objects(&[Attribute::Class(ObjectClass::CERTIFICATE)])
        .map_err(|_| "enumerate native certificates")?;
    let mut result = Vec::new();
    for cert in certs {
        let attrs = session
            .get_attributes(cert, &[AttributeType::Value, AttributeType::Id])
            .map_err(|_| "read installed certificate")?;
        if let [Attribute::Value(value), Attribute::Id(id)] = attrs.as_slice() {
            result.push((id.clone(), value.clone()))
        }
    }
    Ok(result)
}
fn chain_for(leaf: &[u8], certs: &[(Vec<u8>, Vec<u8>)]) -> NativeResult<Vec<Vec<u8>>> {
    let mut chain = vec![leaf.to_vec()];
    loop {
        let (_, child) = X509Certificate::from_der(chain.last().ok_or("invalid chain")?)
            .map_err(|_| "invalid installed certificate")?;
        if child.subject() == child.issuer() {
            break;
        }
        let Some(issuer) = certs.iter().find_map(|(_, der)| {
            let (_, issuer) = X509Certificate::from_der(der).ok()?;
            (issuer.subject() == child.issuer()
                && issuer.is_ca()
                && child.verify_signature(Some(issuer.public_key())).is_ok())
            .then_some((der, issuer))
        }) else {
            break;
        };
        if issuer.1.subject() == issuer.1.issuer() {
            break;
        }
        if chain.len() >= 16 || chain.contains(issuer.0) {
            return Err("invalid installed chain".into());
        }
        chain.push(issuer.0.clone());
    }
    Ok(chain)
}
pub(crate) fn identities() -> NativeResult<Vec<Identity>> {
    let m = module()?;
    let mut identities = Vec::new();
    let mut unavailable = None;
    for slot in m
        .get_slots_with_initialized_token()
        .map_err(|_| "enumerate PKCS#11 slots")?
    {
        let info = m.get_token_info(slot).map_err(|_| "read token identity")?;
        let session = match session(m, slot) {
            Ok(s) => s,
            Err(e) => {
                unavailable = Some(e);
                continue;
            }
        };
        let certs = certificates(&session)?;
        for (id, der) in &certs {
            if id.is_empty() || eligible(der).is_err() || private(&session, id).is_err() {
                continue;
            }
            let key = serde_json::to_vec(&(info.label(), info.serial_number(), id))
                .map_err(|_| "bind token identity")?;
            identities.push(Identity {
                key,
                chain: chain_for(der, &certs)?,
            })
        }
    }
    if identities.is_empty()
        && let Some(e) = unavailable
    {
        return Err(e);
    }
    Ok(identities)
}
pub(crate) fn sign_identity(
    identity: &Identity,
    scheme: SignatureScheme,
    msg: &[u8],
) -> NativeResult<Vec<u8>> {
    let (label, serial, id): (String, String, Vec<u8>) =
        serde_json::from_slice(&identity.key).map_err(|_| "invalid token selection")?;
    let m = module()?;
    let slots = m
        .get_slots_with_initialized_token()
        .map_err(|_| "token unavailable")?;
    let mut matches = slots.into_iter().filter(|&s| {
        m.get_token_info(s)
            .is_ok_and(|i| i.label() == label && i.serial_number() == serial)
    });
    let slot = matches.next().ok_or("token removed")?;
    if matches.next().is_some() {
        return Err("ambiguous token".into());
    }
    let session = session(m, slot)?;
    let certified = certificates(&session)?
        .into_iter()
        .any(|(key, cert)| key == id && cert == identity.chain[0]);
    if !certified {
        return Err("selected certificate unavailable".into());
    }
    let key = private(&session, &id)?;
    use SignatureScheme::*;
    let hash;
    let (mechanism, data) = match scheme {
        EcdsaNistp256Sha256 => {
            hash = Sha256::digest(msg).to_vec();
            (Mechanism::Ecdsa, hash.as_slice())
        }
        EcdsaNistp384Sha384 => {
            hash = Sha384::digest(msg).to_vec();
            (Mechanism::Ecdsa, hash.as_slice())
        }
        RsaPkcs1Sha256 => (Mechanism::Sha256RsaPkcs, msg),
        RsaPkcs1Sha384 => (Mechanism::Sha384RsaPkcs, msg),
        RsaPkcs1Sha512 => (Mechanism::Sha512RsaPkcs, msg),
        RsaPssSha256 => (
            Mechanism::Sha256RsaPkcsPss(PkcsPssParams {
                hash_alg: MechanismType::SHA256,
                mgf: PkcsMgfType::MGF1_SHA256,
                s_len: 32u64.into(),
            }),
            msg,
        ),
        RsaPssSha384 => (
            Mechanism::Sha384RsaPkcsPss(PkcsPssParams {
                hash_alg: MechanismType::SHA384,
                mgf: PkcsMgfType::MGF1_SHA384,
                s_len: 48u64.into(),
            }),
            msg,
        ),
        RsaPssSha512 => (
            Mechanism::Sha512RsaPkcsPss(PkcsPssParams {
                hash_alg: MechanismType::SHA512,
                mgf: PkcsMgfType::MGF1_SHA512,
                s_len: 64u64.into(),
            }),
            msg,
        ),
    };
    let signature = session
        .sign(&mechanism, key, data)
        .map_err(|_| "PKCS#11 signature denied")?;
    match scheme {
        EcdsaNistp256Sha256 => p256::ecdsa::Signature::from_slice(&signature)
            .map(|s| s.to_der().as_bytes().to_vec())
            .map_err(|_| "invalid P-256 signature".into()),
        EcdsaNistp384Sha384 => p384::ecdsa::Signature::from_slice(&signature)
            .map(|s| s.to_der().as_bytes().to_vec())
            .map_err(|_| "invalid P-384 signature".into()),
        _ => Ok(signature),
    }
}
