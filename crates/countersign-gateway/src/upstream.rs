//! One authenticated upstream TLS connection, with signing confined to its grant.

use std::fmt;
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicBool, Ordering},
};

use countersign_protocol::Origin;
use ring::signature::{self, UnparsedPublicKey, VerificationAlgorithm};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error, SignatureAlgorithm, SignatureScheme,
    client::{
        Resumption, WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::ring::default_provider,
    sign::{CertifiedKey, Signer, SigningKey, SingleCertAndKey},
};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{TlsConnector, client::TlsStream};
use x509_parser::{prelude::parse_x509_certificate, public_key::PublicKey};

/// A connection-specific, authenticated relay bound by the supervisor to the
/// live grant, worker, certificate, exact origin and operation deadline.
pub trait SigningRelay: Send + Sync {
    fn sign(
        &self,
        version: rustls::ProtocolVersion,
        scheme: SignatureScheme,
        input: &[u8],
    ) -> Result<Vec<u8>, Error>;
}

struct VerifiedPeer {
    verifier: Arc<WebPkiServerVerifier>,
    version: Arc<OnceLock<rustls::ProtocolVersion>>,
}

impl fmt::Debug for VerifiedPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedPeer")
    }
}

impl ServerCertVerifier for VerifiedPeer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.verifier
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        let proof = self.verifier.verify_tls12_signature(message, cert, dss)?;
        self.version
            .set(rustls::ProtocolVersion::TLSv1_2)
            .map_err(|_| tls_error("repeated peer proof"))?;
        Ok(proof)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        let proof = self.verifier.verify_tls13_signature(message, cert, dss)?;
        self.version
            .set(rustls::ProtocolVersion::TLSv1_3)
            .map_err(|_| tls_error("repeated peer proof"))?;
        Ok(proof)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.verifier.supported_verify_schemes()
    }
}

struct ConnectionKey {
    relay: Arc<dyn SigningRelay>,
    peer: Arc<OnceLock<rustls::ProtocolVersion>>,
    allowed: &'static [SignatureScheme],
    algorithm: SignatureAlgorithm,
    key: Vec<u8>,
    consumed: AtomicBool,
    verified: AtomicBool,
}

#[derive(Clone)]
struct RemoteKey(Arc<ConnectionKey>);

impl fmt::Debug for RemoteKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RemoteKey")
    }
}

impl SigningKey for RemoteKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        self.0
            .allowed
            .iter()
            .find(|scheme| offered.contains(scheme))
            .map(|scheme| {
                Box::new(RemoteSigner {
                    key: self.clone(),
                    scheme: *scheme,
                }) as Box<dyn Signer>
            })
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        self.0.algorithm
    }
}

#[derive(Debug)]
struct RemoteSigner {
    key: RemoteKey,
    scheme: SignatureScheme,
}

impl Signer for RemoteSigner {
    fn sign(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        let key = &self.key.0;
        let version = key
            .peer
            .get()
            .ok_or_else(|| tls_error("destination proof required"))?;
        if key.consumed.swap(true, Ordering::AcqRel) {
            return Err(tls_error("operation already consumed"));
        }
        let signature = key.relay.sign(*version, self.scheme, input)?;
        let algorithm: &dyn VerificationAlgorithm = match self.scheme {
            SignatureScheme::ECDSA_NISTP256_SHA256 => &signature::ECDSA_P256_SHA256_ASN1,
            SignatureScheme::ECDSA_NISTP384_SHA384 => &signature::ECDSA_P384_SHA384_ASN1,
            SignatureScheme::RSA_PSS_SHA256 => &signature::RSA_PSS_2048_8192_SHA256,
            SignatureScheme::RSA_PSS_SHA384 => &signature::RSA_PSS_2048_8192_SHA384,
            SignatureScheme::RSA_PSS_SHA512 => &signature::RSA_PSS_2048_8192_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256 => &signature::RSA_PKCS1_2048_8192_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384 => &signature::RSA_PKCS1_2048_8192_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512 => &signature::RSA_PKCS1_2048_8192_SHA512,
            _ => return Err(tls_error("unsupported client signature scheme")),
        };
        UnparsedPublicKey::new(algorithm, &key.key)
            .verify(input, &signature)
            .map_err(|_| tls_error("client signature did not verify"))?;
        key.verified.store(true, Ordering::Release);
        Ok(signature)
    }
    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

fn tls_error(message: &'static str) -> Error {
    Error::General(message.into())
}

/// The caller must run this handshake on a bounded worker thread, since the
/// synchronous rustls signing callback waits for a deadline-bounded relay.
pub async fn connect<T: AsyncRead + AsyncWrite + Unpin>(
    transport: T,
    origin: &Origin,
    verifier: Arc<WebPkiServerVerifier>,
    chain: Vec<CertificateDer<'static>>,
    selected_sha256: &[u8; 32],
    relay: Arc<dyn SigningRelay>,
) -> std::io::Result<TlsStream<T>> {
    use SignatureScheme::*;
    use std::io::{Error as IoError, ErrorKind::InvalidData};
    let invalid = |msg| IoError::new(InvalidData, msg);
    let leaf = chain
        .first()
        .ok_or_else(|| invalid("missing client identity"))?;
    if ring::digest::digest(&ring::digest::SHA256, leaf.as_ref()).as_ref() != selected_sha256 {
        return Err(invalid("client identity mismatch"));
    }
    let (rest, cert) =
        parse_x509_certificate(leaf).map_err(|_| invalid("invalid client identity"))?;
    if !rest.is_empty() {
        return Err(invalid("trailing certificate data"));
    }
    let pk = cert.public_key();
    let (algorithm, allowed): (_, &'static [SignatureScheme]) = match pk
        .parsed()
        .map_err(|_| invalid("invalid client public key"))?
    {
        PublicKey::RSA(rsa) if (2048..=8192).contains(&rsa.key_size()) => (
            SignatureAlgorithm::RSA,
            &[
                RSA_PSS_SHA256,
                RSA_PSS_SHA384,
                RSA_PSS_SHA512,
                RSA_PKCS1_SHA256,
                RSA_PKCS1_SHA384,
                RSA_PKCS1_SHA512,
            ],
        ),
        PublicKey::EC(_) => {
            let curve = pk
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok())
                .map(|oid| oid.to_id_string());
            match curve.as_deref() {
                Some("1.2.840.10045.3.1.7") => {
                    (SignatureAlgorithm::ECDSA, &[ECDSA_NISTP256_SHA256])
                }
                Some("1.3.132.0.34") => (SignatureAlgorithm::ECDSA, &[ECDSA_NISTP384_SHA384]),
                _ => return Err(invalid("unsupported client curve")),
            }
        }
        _ => return Err(invalid("unsupported client identity")),
    };
    let version = Arc::new(OnceLock::new());
    let key = Arc::new(ConnectionKey {
        relay,
        peer: version.clone(),
        allowed,
        algorithm,
        key: pk.subject_public_key.data.to_vec(),
        consumed: AtomicBool::new(false),
        verified: AtomicBool::new(false),
    });
    let client_auth = CertifiedKey::new(chain, Arc::new(RemoteKey(key.clone())));
    let mut config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(IoError::other)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(VerifiedPeer { verifier, version }))
        .with_client_cert_resolver(Arc::new(SingleCertAndKey::from(client_auth)));
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let server =
        ServerName::try_from(origin.host().to_owned()).map_err(|_| invalid("invalid origin"))?;
    let stream = TlsConnector::from(Arc::new(config))
        .connect(server, transport)
        .await?;
    if !key.verified.load(Ordering::Acquire) {
        return Err(invalid(
            "upstream handshake did not authenticate the client certificate",
        ));
    }
    Ok(stream)
}
