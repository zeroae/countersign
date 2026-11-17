use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde::de::{Error as _, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

#[derive(Debug, Error)]
#[error("invalid or oversized wire value")]
pub struct InvalidValue;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Id(String);

impl Id {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidValue> {
        value.into().try_into()
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Id {
    type Error = InvalidValue;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
            return Err(InvalidValue);
        }
        Ok(Self(value))
    }
}

impl From<Id> for String {
    fn from(value: Id) -> Self {
        value.0
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct FixedBytes<const N: usize>(pub [u8; N]);
pub type Fingerprint = FixedBytes<32>;

impl<const N: usize> FixedBytes<N> {
    pub fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> fmt::Debug for FixedBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FixedBytes<{N}>")
    }
}
impl<const N: usize> Serialize for FixedBytes<N> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(self.0))
    }
}
impl<'de, const N: usize> Deserialize<'de> for FixedBytes<N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        if text.len() != N.div_ceil(3) * 4 {
            return Err(D::Error::custom(InvalidValue));
        }
        let bytes = STANDARD.decode(text).map_err(D::Error::custom)?;
        Ok(Self(
            bytes
                .try_into()
                .map_err(|_| D::Error::custom(InvalidValue))?,
        ))
    }
}

pub const MAX_SIGNING_INPUT: usize = 256 * 1024;
pub const MAX_CHAIN_BYTES: usize = 256 * 1024;
pub const MAX_CERTIFICATES: usize = 16;
pub type SigningInput = Bytes<MAX_SIGNING_INPUT>;
pub type SignatureBytes = Bytes<2048>;

#[derive(Clone, PartialEq, Eq)]
pub struct Bytes<const MAX: usize>(Vec<u8>);

impl<const MAX: usize> Bytes<MAX> {
    pub fn new(value: Vec<u8>) -> Result<Self, InvalidValue> {
        if value.is_empty() || value.len() > MAX {
            return Err(InvalidValue);
        }
        Ok(Self(value))
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl<const MAX: usize> fmt::Debug for Bytes<MAX> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bytes(len={})", self.0.len())
    }
}
impl<const MAX: usize> Serialize for Bytes<MAX> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(&self.0))
    }
}
impl<'de, const MAX: usize> Deserialize<'de> for Bytes<MAX> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        if text.len() > MAX.div_ceil(3) * 4 {
            return Err(D::Error::custom(InvalidValue));
        }
        let bytes = STANDARD.decode(text).map_err(D::Error::custom)?;
        Self::new(bytes).map_err(D::Error::custom)
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct PublicChain(Vec<Bytes<MAX_CHAIN_BYTES>>);
impl PublicChain {
    pub fn new(ders: Vec<Vec<u8>>) -> Result<Self, InvalidValue> {
        if ders.is_empty() || ders.len() > MAX_CERTIFICATES {
            return Err(InvalidValue);
        }
        let mut total = 0usize;
        let mut certs = Vec::with_capacity(ders.len());
        for der in ders {
            let cert = Bytes::new(der)?;
            total += cert.0.len();
            if total > MAX_CHAIN_BYTES {
                return Err(InvalidValue);
            }
            certs.push(cert);
        }
        Ok(Self(certs))
    }
    pub fn as_slice(&self) -> &[Bytes<MAX_CHAIN_BYTES>] {
        &self.0
    }
}
impl<'de> Deserialize<'de> for PublicChain {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct ChainVisitor;
        impl<'de> Visitor<'de> for ChainVisitor {
            type Value = PublicChain;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a bounded nonempty public DER chain")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut certs = Vec::new();
                let mut total = 0;
                while let Some(cert) = seq.next_element::<Bytes<MAX_CHAIN_BYTES>>()? {
                    total += cert.0.len();
                    if certs.len() == MAX_CERTIFICATES || total > MAX_CHAIN_BYTES {
                        return Err(A::Error::custom(InvalidValue));
                    }
                    certs.push(cert);
                }
                if certs.is_empty() {
                    return Err(A::Error::custom(InvalidValue));
                }
                Ok(PublicChain(certs))
            }
        }
        d.deserialize_seq(ChainVisitor)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CompactJws(String);
impl CompactJws {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for CompactJws {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CompactJws([redacted])")
    }
}
impl TryFrom<String> for CompactJws {
    type Error = InvalidValue;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        if s.len() > 16384 {
            return Err(InvalidValue);
        }
        let mut parts = s.split('.');
        for i in 0..3 {
            let bytes = URL_SAFE_NO_PAD
                .decode(parts.next().ok_or(InvalidValue)?)
                .map_err(|_| InvalidValue)?;
            if bytes.is_empty() || (i == 2 && bytes.len() != 64) {
                return Err(InvalidValue);
            }
        }
        if parts.next().is_some() {
            return Err(InvalidValue);
        }
        Ok(Self(s))
    }
}
impl From<CompactJws> for String {
    fn from(value: CompactJws) -> Self {
        value.0
    }
}
