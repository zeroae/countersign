//! One app-owned NSS user database per pairing. Electron may already own the
//! global NSS context. Never shut it down or initialize/reset a user's token.
use super::*;
use crate::{NativeResult, random_id};
use sha2::{Digest, Sha256};
use std::{
    ffi::{CString, c_char, c_int, c_uint, c_ulong, c_void},
    fs,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    ptr,
};
use x509_parser::prelude::*;
type Ptr = *mut c_void;
#[repr(C)]
struct Item {
    kind: c_int,
    data: *mut u8,
    len: c_uint,
}
impl Item {
    fn read(bytes: &[u8]) -> Self {
        Self {
            kind: 0,
            data: bytes.as_ptr() as *mut u8,
            len: bytes.len() as c_uint,
        }
    }
}
#[link(name = "nss3")]
unsafe extern "C" {
    fn NSS_IsInitialized() -> c_int;
    fn NSS_NoDB_Init(path: *const c_char) -> c_int;
    fn SECMOD_OpenUserDB(spec: *const c_char) -> Ptr;
    fn SECMOD_CloseUserDB(slot: Ptr) -> c_int;
    fn PK11_FreeSlot(slot: Ptr);
    fn PK11_InitPin(slot: Ptr, old: *const c_char, new: *const c_char) -> c_int;
    fn PK11_CheckUserPassword(slot: Ptr, password: *const c_char) -> c_int;
    fn PK11_Logout(slot: Ptr) -> c_int;
    fn PK11_GenerateKeyPairWithFlags(
        slot: Ptr,
        mech: c_ulong,
        params: Ptr,
        public: *mut Ptr,
        flags: u32,
        ctx: Ptr,
    ) -> Ptr;
    fn PK11_ReadRawAttribute(obj_type: c_int, key: Ptr, attr: c_ulong, value: *mut Item) -> c_int;
    fn PK11_GetLowLevelKeyIDForPrivateKey(key: Ptr) -> *mut Item;
    fn PK11_FindKeyByKeyID(slot: Ptr, id: *mut Item, ctx: Ptr) -> Ptr;
    fn SECKEY_ConvertToPublicKey(key: Ptr) -> Ptr;
    fn SECKEY_EncodeDERSubjectPublicKeyInfo(key: Ptr) -> *mut Item;
    fn SECITEM_FreeItem(item: *mut Item, free: c_int);
    fn SECKEY_DestroyPrivateKey(key: Ptr);
    fn SECKEY_DestroyPublicKey(key: Ptr);
    fn PK11_SignWithMechanism(
        key: Ptr,
        mech: c_ulong,
        params: *mut Item,
        out: *mut Item,
        input: *mut Item,
    ) -> c_int;
}

fn path(locator: &str) -> NativeResult<PathBuf> {
    let data = data_home()?;
    Ok(data.join("countersign").join("pairings").join(locator))
}
struct Slot(Ptr);
impl Slot {
    fn open(locator: &str, pin: &[u8], fresh: bool) -> NativeResult<Self> {
        let dir = path(locator)?;
        let name = dir.to_str().ok_or("invalid user directory")?;
        if name.contains(['\'', '\\', '\n', '\r']) {
            return Err("invalid user directory".into());
        }
        // Unique token name, including on reconnect within the same process.
        let spec = CString::new(format!(
            "configDir='sql:{name}' tokenDescription='cs-{}'",
            &locator[locator.len() - 20..]
        ))
        .map_err(|_| "invalid user directory")?;
        let mut password = Zeroizing::new(pin.to_vec());
        if password.is_empty() || password.contains(&0) {
            return Err("invalid login secret".into());
        }
        password.push(0);
        unsafe {
            if NSS_IsInitialized() == 0 && NSS_NoDB_Init(ptr::null()) != 0 {
                return Err("NSS unavailable".into());
            }
            let slot = SECMOD_OpenUserDB(spec.as_ptr());
            if slot.is_null() {
                return Err("pairing database unavailable".into());
            }
            let slot = Self(slot);
            if fresh && PK11_InitPin(slot.0, ptr::null(), password.as_ptr().cast()) != 0 {
                return Err("NSS token PIN initialization failed".into());
            }
            if PK11_CheckUserPassword(slot.0, password.as_ptr().cast()) != 0 {
                return Err("NSS token unlock denied".into());
            }
            Ok(slot)
        }
    }
}
impl Drop for Slot {
    fn drop(&mut self) {
        unsafe {
            PK11_Logout(self.0);
            SECMOD_CloseUserDB(self.0);
            PK11_FreeSlot(self.0)
        }
    }
}
struct Private(Ptr);
impl Drop for Private {
    fn drop(&mut self) {
        unsafe { SECKEY_DestroyPrivateKey(self.0) }
    }
}
fn verify_nonextractable(key: &Private) -> NativeResult<()> {
    // Read CKA_SENSITIVE and CKA_EXTRACTABLE from the token itself.
    for (attr, expected) in [(0x103, 1u8), (0x162, 0u8)] {
        let mut value = Item {
            kind: 0,
            data: ptr::null_mut(),
            len: 0,
        };
        if unsafe { PK11_ReadRawAttribute(1, key.0, attr, &mut value) } != 0 {
            return Err("cannot verify NSS key protection".into());
        }
        let valid = unsafe { value.len == 1 && !value.data.is_null() && *value.data == expected };
        unsafe { SECITEM_FreeItem(&mut value, 0) };
        if !valid {
            return Err("unprotected NSS pairing key refused".into());
        }
    }
    Ok(())
}
struct Public(Ptr);
impl Drop for Public {
    fn drop(&mut self) {
        unsafe { SECKEY_DestroyPublicKey(self.0) }
    }
}

fn take_item(item: *mut Item) -> NativeResult<Vec<u8>> {
    if item.is_null() {
        return Err("NSS public attribute unavailable".into());
    }
    // NSS owns this SECItem. Copy only the returned public attribute, then free both fields.
    unsafe {
        let bytes = if (*item).data.is_null() || (*item).len == 0 || (*item).len > 8192 {
            Err("invalid public attribute".into())
        } else {
            Ok(std::slice::from_raw_parts((*item).data, (*item).len as usize).to_vec())
        };
        SECITEM_FreeItem(item, 1);
        bytes
    }
}
fn point(public: &Public) -> NativeResult<Vec<u8>> {
    let spki = take_item(unsafe { SECKEY_EncodeDERSubjectPublicKeyInfo(public.0) })?;
    let (_, pk) =
        SubjectPublicKeyInfo::from_der(&spki).map_err(|_| "invalid pairing public key")?;
    let point = pk.subject_public_key.data.to_vec();
    p256::PublicKey::from_sec1_bytes(&point).map_err(|_| "invalid P-256 public key")?;
    Ok(point)
}

pub(crate) fn create_pairing(locator: &str) -> NativeResult<Vec<u8>> {
    let dir = path(locator)?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir.parent().ok_or("invalid user directory")?)
        .map_err(|_| "create pairing directory")?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(|_| "pairing locator already exists or cannot create store")?;
    let result = (|| {
        let service =
            SecretService::connect(EncryptionType::Dh).map_err(|_| "Secret Service unavailable")?;
        let collection = protected_collection(&service)?;
        let pin = Zeroizing::new(random_id()?);
        let slot = Slot::open(locator, pin.as_bytes(), true)?;
        let oid = hex::decode("06082a8648ce3d030107").expect("P-256 OID");
        let mut params = Item::read(&oid);
        let mut pubkey = ptr::null_mut();
        // NSS TOKEN | PRIVATE | SENSITIVE | UNEXTRACTABLE, explicit even on software tokens.
        let key = unsafe {
            PK11_GenerateKeyPairWithFlags(
                slot.0,
                0x1040,
                (&mut params as *mut Item).cast(),
                &mut pubkey,
                0x1 | 0x4 | 0x40 | 0x200,
                ptr::null_mut(),
            )
        };
        if key.is_null() {
            return Err("generate protected NSS pairing key".into());
        }
        let key = Private(key);
        verify_nonextractable(&key)?;
        if pubkey.is_null() {
            return Err("missing NSS public key".into());
        }
        let pubkey = Public(pubkey);
        let id = take_item(unsafe { PK11_GetLowLevelKeyIDForPrivateKey(key.0) })?;
        let public = point(&pubkey)?;
        fs::write(dir.join("public-key-id"), id).map_err(|_| "persist public locator")?;
        collection
            .create_item(
                "Countersign pairing",
                attributes("pairing", "locator", locator),
                pin.as_bytes(),
                false,
                "text/plain",
            )
            .map_err(|_| "protect NSS unlock credential")?;
        Ok(public)
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&dir);
    }
    result
}
fn with_key<T>(locator: &str, work: impl FnOnce(&Private) -> NativeResult<T>) -> NativeResult<T> {
    let pin = secret("pairing", "locator", locator)?;
    let id_bytes = fs::read(path(locator)?.join("public-key-id"))
        .map_err(|_| "pairing locator unavailable")?;
    if id_bytes.is_empty() || id_bytes.len() > 128 {
        return Err("corrupt public locator".into());
    }
    let slot = Slot::open(locator, &pin, false)?;
    let mut id = Item::read(&id_bytes);
    let key = unsafe { PK11_FindKeyByKeyID(slot.0, &mut id, ptr::null_mut()) };
    if key.is_null() {
        return Err("pairing key missing".into());
    }
    let key = Private(key);
    verify_nonextractable(&key)?;
    work(&key)
}
pub(crate) fn pairing_public(locator: &str) -> NativeResult<Vec<u8>> {
    with_key(locator, |key| {
        let public = unsafe { SECKEY_ConvertToPublicKey(key.0) };
        if public.is_null() {
            return Err("pairing public key unavailable".into());
        }
        point(&Public(public))
    })
}
pub(crate) fn pairing_sign(locator: &str, bytes: &[u8]) -> NativeResult<Vec<u8>> {
    with_key(locator, |key| {
        let hash = Sha256::digest(bytes);
        let mut input = Item::read(&hash);
        let mut sig = vec![0; 64];
        let mut output = Item {
            kind: 0,
            data: sig.as_mut_ptr(),
            len: sig.len() as u32,
        };
        if unsafe {
            PK11_SignWithMechanism(key.0, 0x1041, ptr::null_mut(), &mut output, &mut input)
        } != 0
            || output.len != 64
        {
            return Err("NSS pairing sign denied".into());
        }
        Ok(sig)
    })
}
pub(crate) fn retire_pairing(locator: &str) -> NativeResult<()> {
    let service =
        SecretService::connect(EncryptionType::Dh).map_err(|_| "Secret Service unavailable")?;
    let collection = service
        .get_default_collection()
        .map_err(|_| "login keyring unavailable")?;
    let items = collection
        .search_items(attributes("pairing", "locator", locator))
        .map_err(|_| "locate pairing credential")?;
    for item in items {
        item.delete().map_err(|_| "retire pairing credential")?;
    }
    let dir = path(locator)?;
    if dir.exists() {
        fs::remove_dir_all(dir).map_err(|_| "remove app-owned pairing store")?;
    }
    Ok(())
}
