//! CurrentUser/My discovery and CNG-only signing. CryptoAPI legacy CSP keys
//! are excluded because their custody and UI contracts differ from CNG.
use crate::{Identity, NativeResult, eligible};
use countersign_protocol::wire::SignatureScheme;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::{ffi::c_void, ptr};
use windows_sys::Win32::Security::Cryptography::*;
use x509_parser::prelude::*;

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
fn check(value: i32, label: &str) -> NativeResult<()> {
    if value != 0 {
        Err(format!("{label} failed ({value:#x})"))
    } else {
        Ok(())
    }
}
struct Handle(usize);
impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe {
                NCryptFreeObject(self.0);
            }
        }
    }
}
fn provider() -> NativeResult<Handle> {
    let mut provider = 0;
    check(
        unsafe { NCryptOpenStorageProvider(&mut provider, MS_KEY_STORAGE_PROVIDER, 0) },
        "CNG provider",
    )?;
    Ok(Handle(provider))
}
fn pairing(locator: &str) -> NativeResult<Handle> {
    let provider = provider()?;
    let mut key = 0;
    check(
        unsafe { NCryptOpenKey(provider.0, &mut key, wide(locator).as_ptr(), 0, 0) },
        "reopen pairing credential",
    )?;
    let key = Handle(key);
    check_protection(key.0)?;
    Ok(key)
}
fn check_protection(key: usize) -> NativeResult<()> {
    let mut policy = [0u8; 4];
    let mut len = 0;
    check(
        unsafe {
            NCryptGetProperty(
                key,
                NCRYPT_EXPORT_POLICY_PROPERTY,
                policy.as_mut_ptr(),
                4,
                &mut len,
                0,
            )
        },
        "verify pairing key export policy",
    )?;
    if len != 4 || u32::from_le_bytes(policy) != 0 {
        return Err("CNG pairing key allows export".into());
    }
    Ok(())
}
fn public(key: usize) -> NativeResult<Vec<u8>> {
    // A P-256 BCRYPT_ECCPUBLIC_BLOB contains an 8-byte header and the 64 public point bytes.
    let mut buf = [0u8; 72];
    let mut len = 0;
    check(
        unsafe {
            NCryptExportKey(
                key,
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                ptr::null(),
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut len,
                0,
            )
        },
        "read public key",
    )?;
    if len != 72 || buf[4..8] != 32u32.to_le_bytes() {
        return Err("invalid pairing public key".into());
    }
    let sec1 = [&[4u8][..], &buf[8..]].concat();
    p256::PublicKey::from_sec1_bytes(&sec1).map_err(|_| "invalid P-256 point")?;
    Ok(sec1)
}
pub(crate) fn create_pairing(locator: &str) -> NativeResult<Vec<u8>> {
    let provider = provider()?;
    let mut handle = 0;
    check(
        unsafe {
            NCryptCreatePersistedKey(
                provider.0,
                &mut handle,
                BCRYPT_ECDSA_P256_ALGORITHM,
                wide(locator).as_ptr(),
                0,
                0,
            )
        },
        "create pairing credential",
    )?;
    let key = Handle(handle);
    check(
        unsafe {
            NCryptSetProperty(
                key.0,
                NCRYPT_EXPORT_POLICY_PROPERTY,
                0u32.to_le_bytes().as_ptr(),
                4,
                0,
            )
        },
        "protect key",
    )?;
    check(
        unsafe {
            NCryptSetProperty(
                key.0,
                NCRYPT_KEY_USAGE_PROPERTY,
                NCRYPT_ALLOW_SIGNING_FLAG.to_le_bytes().as_ptr(),
                4,
                0,
            )
        },
        "set signing usage",
    )?;
    check(
        unsafe { NCryptFinalizeKey(key.0, 0) },
        "persist protected credential",
    )?;
    if let Err(err) = check_protection(key.0) {
        // Only delete the newly generated app-owned object.
        let mut key = key;
        if unsafe { NCryptDeleteKey(key.0, 0) } == 0 {
            key.0 = 0;
        }
        return Err(err);
    }
    public(key.0)
}
pub(crate) fn pairing_public(locator: &str) -> NativeResult<Vec<u8>> {
    public(pairing(locator)?.0)
}
pub(crate) fn retire_pairing(locator: &str) -> NativeResult<()> {
    let mut key = pairing(locator)?;
    check(unsafe { NCryptDeleteKey(key.0, 0) }, "retire pairing key")?;
    key.0 = 0;
    Ok(())
}
fn sign(key: usize, scheme: SignatureScheme, msg: &[u8]) -> NativeResult<Vec<u8>> {
    use SignatureScheme::*;
    let (hash, alg) = match scheme {
        EcdsaNistp256Sha256 | RsaPssSha256 | RsaPkcs1Sha256 => {
            (Sha256::digest(msg).to_vec(), BCRYPT_SHA256_ALGORITHM)
        }
        EcdsaNistp384Sha384 | RsaPssSha384 | RsaPkcs1Sha384 => {
            (Sha384::digest(msg).to_vec(), BCRYPT_SHA384_ALGORITHM)
        }
        RsaPssSha512 | RsaPkcs1Sha512 => (Sha512::digest(msg).to_vec(), BCRYPT_SHA512_ALGORITHM),
    };
    let pss = BCRYPT_PSS_PADDING_INFO {
        pszAlgId: alg,
        cbSalt: hash.len() as u32,
    };
    let pkcs = BCRYPT_PKCS1_PADDING_INFO { pszAlgId: alg };
    let (padding, flags) = match scheme {
        RsaPssSha256 | RsaPssSha384 | RsaPssSha512 => (
            (&pss as *const BCRYPT_PSS_PADDING_INFO).cast::<c_void>(),
            NCRYPT_PAD_PSS_FLAG,
        ),
        RsaPkcs1Sha256 | RsaPkcs1Sha384 | RsaPkcs1Sha512 => (
            (&pkcs as *const BCRYPT_PKCS1_PADDING_INFO).cast::<c_void>(),
            NCRYPT_PAD_PKCS1_FLAG,
        ),
        _ => (ptr::null(), 0),
    };
    let mut buf = vec![0; 2048];
    let mut len = 0;
    check(
        unsafe {
            NCryptSignHash(
                key,
                padding,
                hash.as_ptr(),
                hash.len() as u32,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut len,
                flags,
            )
        },
        "native signing",
    )?;
    buf.truncate(len as usize);
    Ok(buf)
}
pub(crate) fn pairing_sign(locator: &str, msg: &[u8]) -> NativeResult<Vec<u8>> {
    sign(
        pairing(locator)?.0,
        SignatureScheme::EcdsaNistp256Sha256,
        msg,
    )
}

struct Store(HCERTSTORE);
impl Drop for Store {
    fn drop(&mut self) {
        unsafe {
            CertCloseStore(self.0, 0);
        }
    }
}
struct Cert(*const CERT_CONTEXT);
impl Drop for Cert {
    fn drop(&mut self) {
        unsafe {
            CertFreeCertificateContext(self.0);
        }
    }
}
fn certs() -> NativeResult<Vec<Cert>> {
    let store = Store(unsafe { CertOpenSystemStoreW(0, wide("MY").as_ptr()) });
    if store.0.is_null() {
        return Err("open CurrentUser/My".into());
    }
    let mut result = vec![];
    unsafe {
        let mut cert = ptr::null_mut();
        loop {
            // Each enumeration frees its previous pointer. Only the duplicated
            // references leave the loop and their RAII guards free them.
            cert = CertEnumCertificatesInStore(store.0, cert);
            if cert.is_null() {
                break;
            }
            let copy = CertDuplicateCertificateContext(cert);
            if !copy.is_null() {
                result.push(Cert(copy))
            }
        }
    }
    Ok(result)
}
fn der(cert: *const CERT_CONTEXT) -> NativeResult<Vec<u8>> {
    if cert.is_null() {
        return Err("null certificate".into());
    }
    unsafe {
        if (*cert).pbCertEncoded.is_null()
            || (*cert).cbCertEncoded == 0
            || (*cert).cbCertEncoded > 262144
        {
            return Err("invalid certificate size".into());
        }
        Ok(
            std::slice::from_raw_parts((*cert).pbCertEncoded, (*cert).cbCertEncoded as usize)
                .to_vec(),
        )
    }
}

fn acquire<T>(
    cert: &Cert,
    silent: bool,
    work: impl FnOnce(usize) -> NativeResult<T>,
) -> NativeResult<T> {
    let mut key = 0;
    let mut spec = 0;
    let mut free = 0;
    let flags =
        CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | if silent { CRYPT_ACQUIRE_SILENT_FLAG } else { 0 };
    if unsafe {
        CryptAcquireCertificatePrivateKey(
            cert.0,
            flags,
            ptr::null(),
            &mut key,
            &mut spec,
            &mut free,
        )
    } == 0
    {
        return Err("native key access denied".into());
    }
    let _owned = if free != 0 { Some(Handle(key)) } else { None };
    if spec != CERT_NCRYPT_KEY_SPEC {
        return Err("unsupported key provider".into());
    }
    work(key)
}
fn chain(cert: &Cert) -> NativeResult<Vec<Vec<u8>>> {
    let params = CERT_CHAIN_PARA {
        cbSize: std::mem::size_of::<CERT_CHAIN_PARA>() as u32,
        ..Default::default()
    };
    let mut ctx = ptr::null_mut();
    unsafe {
        if CertGetCertificateChain(
            ptr::null_mut(),
            cert.0,
            ptr::null(),
            (*cert.0).hCertStore,
            &params,
            CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL | CERT_CHAIN_DISABLE_AIA,
            ptr::null(),
            &mut ctx,
        ) == 0
        {
            return Err("build installed certificate chain".into());
        }
        let result = (|| {
            if (*ctx).cChain == 0 {
                return Err("missing certificate chain".into());
            }
            let simple = *(*ctx).rgpChain;
            if (*simple).cElement > 16 {
                return Err("chain exceeds limit".into());
            }
            let mut chain = Vec::new();
            for i in 0..(*simple).cElement as usize {
                let cert = der((**(*simple).rgpElement.add(i)).pCertContext)?;
                if i > 0
                    && X509Certificate::from_der(&cert)
                        .is_ok_and(|(_, c)| c.subject() == c.issuer())
                {
                    break;
                }
                chain.push(cert)
            }
            Ok(chain)
        })();
        CertFreeCertificateChain(ctx);
        result
    }
}
pub(crate) fn identities() -> NativeResult<Vec<Identity>> {
    let mut result = Vec::new();
    for cert in certs()? {
        let leaf = der(cert.0)?;
        if eligible(&leaf).is_err() {
            continue;
        }
        // Inspect CNG key metadata without signing or opening a PIN dialog.
        let mut bytes = 0;
        if unsafe {
            CertGetCertificateContextProperty(
                cert.0,
                CERT_KEY_PROV_INFO_PROP_ID,
                ptr::null_mut(),
                &mut bytes,
            )
        } == 0
            || bytes == 0
        {
            continue;
        }
        let mut info = vec![0usize; (bytes as usize).div_ceil(std::mem::size_of::<usize>())];
        if unsafe {
            CertGetCertificateContextProperty(
                cert.0,
                CERT_KEY_PROV_INFO_PROP_ID,
                info.as_mut_ptr().cast(),
                &mut bytes,
            )
        } == 0
            || (bytes as usize) < std::mem::size_of::<CRYPT_KEY_PROV_INFO>()
        {
            continue;
        }
        if unsafe { (*info.as_ptr().cast::<CRYPT_KEY_PROV_INFO>()).dwProvType } != 0 {
            continue;
        }
        result.push(Identity {
            key: Sha256::digest(&leaf).to_vec(),
            chain: chain(&cert)?,
        })
    }
    Ok(result)
}
pub(crate) fn sign_identity(
    identity: &Identity,
    scheme: SignatureScheme,
    msg: &[u8],
) -> NativeResult<Vec<u8>> {
    let cert = certs()?
        .into_iter()
        .find(|c| {
            der(c.0).is_ok_and(|der| {
                der == identity.chain[0] && Sha256::digest(&der).to_vec() == identity.key
            })
        })
        .ok_or("selected certificate removed")?;
    let raw = acquire(&cert, false, |key| sign(key, scheme, msg))?;
    match scheme {
        SignatureScheme::EcdsaNistp256Sha256 => p256::ecdsa::Signature::from_slice(&raw)
            .map(|s| s.to_der().as_bytes().to_vec())
            .map_err(|_| "invalid P-256 signature".into()),
        SignatureScheme::EcdsaNistp384Sha384 => p384::ecdsa::Signature::from_slice(&raw)
            .map(|s| s.to_der().as_bytes().to_vec())
            .map_err(|_| "invalid P-384 signature".into()),
        _ => Ok(raw),
    }
}
