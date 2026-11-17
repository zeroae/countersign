//! The system Keychain mediates access, including PIN/touch for token-backed identities.
use crate::{Identity, NativeResult, eligible};
use core_foundation::{
    base::TCFType,
    boolean::CFBoolean,
    dictionary::CFDictionary,
    number::CFNumber,
    string::{CFString, CFStringRef},
};
use countersign_protocol::wire::SignatureScheme;
use security_framework::{
    identity::SecIdentity,
    item::{ItemClass, ItemSearchOptions, KeyClass, Limit, Reference, SearchResult},
    key::{Algorithm, SecKey},
    policy::SecPolicy,
    trust::SecTrust,
};
use security_framework_sys::item::*;
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecAttrIsExtractable: CFStringRef;
}

fn key(locator: &str) -> NativeResult<SecKey> {
    let mut q = ItemSearchOptions::new();
    q.class(ItemClass::key())
        .key_class(KeyClass::private())
        .label(locator)
        .limit(Limit::All)
        .load_refs(true);
    let mut results = q.search().map_err(|_| "pairing key locked or missing")?;
    if results.len() == 1
        && let Some(SearchResult::Ref(Reference::Key(key))) = results.pop()
    {
        return Ok(key);
    }
    Err("ambiguous or missing pairing key".into())
}
fn point(key: &SecKey) -> NativeResult<Vec<u8>> {
    let public = key.public_key().ok_or("Keychain public key unavailable")?;
    let point = public
        .external_representation()
        .ok_or("Keychain public representation unavailable")?
        .to_vec();
    p256::PublicKey::from_sec1_bytes(&point).map_err(|_| "invalid pairing public key")?;
    Ok(point)
}
pub(crate) fn create_pairing(locator: &str) -> NativeResult<Vec<u8>> {
    let label = CFString::new(locator);
    let bits = CFNumber::from(256);
    // Apply non-extractability specifically to the private half. The public
    // half remains available for device proof verification and pairing.
    let attrs = unsafe {
        let private = CFDictionary::from_CFType_pairs(&[
            (
                CFString::wrap_under_get_rule(kSecAttrIsPermanent).as_CFType(),
                CFBoolean::true_value().as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrIsExtractable).as_CFType(),
                CFBoolean::false_value().as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrLabel).as_CFType(),
                label.as_CFType(),
            ),
        ]);
        CFDictionary::from_CFType_pairs(&[
            (
                CFString::wrap_under_get_rule(kSecAttrKeyType).as_CFType(),
                CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom).as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrKeySizeInBits).as_CFType(),
                bits.as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrLabel).as_CFType(),
                label.as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecPrivateKeyAttrs).as_CFType(),
                private.as_CFType(),
            ),
        ])
    };
    #[allow(deprecated)]
    let key = SecKey::generate(attrs.into_untyped())
        .map_err(|_| "create non-exportable Keychain pairing key")?;
    point(&key)
}
pub(crate) fn pairing_public(locator: &str) -> NativeResult<Vec<u8>> {
    point(&key(locator)?)
}
pub(crate) fn pairing_sign(locator: &str, msg: &[u8]) -> NativeResult<Vec<u8>> {
    let der = key(locator)?
        .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, msg)
        .map_err(|_| "pairing signature denied")?;
    Ok(p256::ecdsa::Signature::from_der(&der)
        .map_err(|_| "invalid native pairing signature")?
        .to_bytes()
        .to_vec())
}
pub(crate) fn retire_pairing(locator: &str) -> NativeResult<()> {
    key(locator)?
        .delete()
        .map_err(|_| "Keychain retirement denied".into())
}

fn installed() -> NativeResult<Vec<SecIdentity>> {
    let mut search = ItemSearchOptions::new();
    search
        .class(ItemClass::identity())
        .limit(Limit::All)
        .load_refs(true);
    match search.search() {
        Ok(results) => Ok(results
            .into_iter()
            .filter_map(|r| match r {
                SearchResult::Ref(Reference::Identity(i)) => Some(i),
                _ => None,
            })
            .collect()),
        Err(e) if e.code() == -25300 => Ok(vec![]),
        Err(_) => Err("Keychain identity discovery denied".into()),
    }
}
pub(crate) fn identities() -> NativeResult<Vec<Identity>> {
    let mut items = Vec::new();
    for identity in installed()? {
        let cert = identity
            .certificate()
            .map_err(|_| "read public certificate")?;
        let leaf = cert.to_der();
        if eligible(&leaf).is_err() {
            continue;
        }
        let mut trust = SecTrust::create_with_certificates(&[cert], &[SecPolicy::create_x509()])
            .map_err(|_| "build Keychain certificate chain")?;
        trust
            .set_network_fetch_allowed(false)
            .map_err(|_| "disable certificate URL retrieval")?;
        // The Broker has the managed site trust. Build with local intermediates
        // even when the desktop does not trust the site's client issuing CA.
        let _ = trust.evaluate_with_error();
        let mut chain = vec![leaf.clone()];
        for cert in trust.chain().into_iter().skip(1) {
            let der = cert.to_der();
            if X509Certificate::from_der(&der).is_ok_and(|(_, c)| c.issuer() == c.subject()) {
                break;
            }
            chain.push(der);
        }
        items.push(Identity {
            key: Sha256::digest(&leaf).to_vec(),
            chain,
        });
    }
    Ok(items)
}
pub(crate) fn sign_identity(
    identity: &Identity,
    scheme: SignatureScheme,
    msg: &[u8],
) -> NativeResult<Vec<u8>> {
    let mut found = installed()?.into_iter().filter(|id| {
        id.certificate().is_ok_and(|c| {
            c.to_der() == identity.chain[0] && Sha256::digest(c.to_der()).as_slice() == identity.key
        })
    });
    let signing = found.next().ok_or("Keychain identity removed")?;
    if found.next().is_some() {
        return Err("ambiguous Keychain identity".into());
    }
    let key = signing
        .private_key()
        .map_err(|_| "Keychain signing access denied")?;
    use SignatureScheme::*;
    let algorithm = match scheme {
        EcdsaNistp256Sha256 => Algorithm::ECDSASignatureMessageX962SHA256,
        EcdsaNistp384Sha384 => Algorithm::ECDSASignatureMessageX962SHA384,
        RsaPssSha256 => Algorithm::RSASignatureMessagePSSSHA256,
        RsaPssSha384 => Algorithm::RSASignatureMessagePSSSHA384,
        RsaPssSha512 => Algorithm::RSASignatureMessagePSSSHA512,
        RsaPkcs1Sha256 => Algorithm::RSASignatureMessagePKCS1v15SHA256,
        RsaPkcs1Sha384 => Algorithm::RSASignatureMessagePKCS1v15SHA384,
        RsaPkcs1Sha512 => Algorithm::RSASignatureMessagePKCS1v15SHA512,
    };
    key.create_signature(algorithm, msg)
        .map_err(|_| "Keychain signing denied".into())
}
