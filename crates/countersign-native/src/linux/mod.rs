mod pairing;
mod token;
pub(crate) use pairing::{create_pairing, pairing_public, pairing_sign, retire_pairing};
pub(crate) use token::{identities, sign_identity};

use crate::NativeResult;
use secret_service::{
    EncryptionType,
    blocking::{Collection, SecretService},
};
use std::collections::HashMap;
use zeroize::Zeroizing;

fn attributes<'a>(kind: &'a str, field: &'a str, value: &'a str) -> HashMap<&'a str, &'a str> {
    HashMap::from([
        ("application", "Countersign"),
        ("kind", kind),
        (field, value),
    ])
}

fn data_home() -> NativeResult<std::path::PathBuf> {
    let dir = std::env::var_os("XDG_DATA_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|p| std::path::PathBuf::from(p).join(".local/share"))
        })
        .ok_or("user data directory unavailable")?;
    if !dir.is_absolute() {
        return Err("invalid user data directory".into());
    }
    Ok(dir)
}

fn protected_collection<'a>(service: &'a SecretService<'a>) -> NativeResult<Collection<'a>> {
    use std::io::Read;
    let collection = service
        .get_default_collection()
        .map_err(|_| "login keyring unavailable")?;
    // Secret Service has persistent, session-only and even plaintext backends.
    // The supported GNOME profile requires its encrypted binary login keyring.
    if collection.collection_path.as_str() != "/org/freedesktop/secrets/collection/login" {
        return Err("configure the encrypted GNOME login collection as default".into());
    }
    let mut magic = [0u8; 16];
    std::fs::File::open(data_home()?.join("keyrings/login.keyring"))
        .and_then(|mut file| file.read_exact(&mut magic))
        .map_err(|_| "encrypted login keyring unavailable")?;
    if &magic != b"GnomeKeyring\n\r\0\n" {
        return Err("plaintext or unsupported login keyring".into());
    }
    collection
        .ensure_unlocked()
        .map_err(|_| "login keyring locked")?;
    Ok(collection)
}

fn secret(kind: &str, field: &str, value: &str) -> NativeResult<Zeroizing<Vec<u8>>> {
    let service =
        SecretService::connect(EncryptionType::Dh).map_err(|_| "Secret Service unavailable")?;
    let collection = protected_collection(&service)?;
    let items = collection
        .search_items(attributes(kind, field, value))
        .map_err(|_| "keyring lookup failed")?;
    let [item] = &items[..] else {
        return Err("missing or ambiguous provider unlock credential".into());
    };
    let bytes = item
        .get_secret()
        .map_err(|_| "provider unlock unavailable")?;
    if bytes.is_empty() {
        return Err("empty provider unlock refused".into());
    }
    Ok(Zeroizing::new(bytes))
}
