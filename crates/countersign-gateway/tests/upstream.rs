use countersign_gateway::upstream::{SigningRelay, connect};
use countersign_protocol::Origin;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::{
    RootCertStore, ServerConfig, client::WebPkiServerVerifier, crypto::ring::default_provider,
    server::WebPkiClientVerifier,
};
use rustls_pki_types::PrivatePkcs8KeyDer;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct TestRelay {
    key: KeyPair,
    calls: AtomicUsize,
    corrupt: bool,
}
impl SigningRelay for TestRelay {
    fn sign(
        &self,
        _: rustls::ProtocolVersion,
        _: rustls::SignatureScheme,
        data: &[u8],
    ) -> Result<Vec<u8>, rustls::Error> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        let mut signature = rcgen::SigningKey::sign(&self.key, data).unwrap();
        if self.corrupt {
            signature[0] ^= 1;
        }
        Ok(signature)
    }
}

async fn handshake(
    version: &'static rustls::SupportedProtocolVersion,
    host: &str,
    client_auth: bool,
    corrupt: bool,
) -> (bool, usize) {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    let issuer = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
    let server_key = KeyPair::generate().unwrap();
    let server_certificate = CertificateParams::new(vec!["protected.test".to_owned()])
        .unwrap()
        .signed_by(&server_key, &issuer)
        .unwrap();
    let relay = Arc::new(TestRelay {
        key: KeyPair::generate().unwrap(),
        calls: AtomicUsize::new(0),
        corrupt,
    });
    let client_certificate = CertificateParams::default()
        .signed_by(&relay.key, &issuer)
        .unwrap();
    let selected: [u8; 32] = ring::digest::digest(&ring::digest::SHA256, client_certificate.der())
        .as_ref()
        .try_into()
        .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(issuer.der().clone()).unwrap();
    let roots = Arc::new(roots);
    let provider = Arc::new(default_provider());
    let server = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[version])
        .unwrap();
    let server = if client_auth {
        server.with_client_cert_verifier(
            WebPkiClientVerifier::builder_with_provider(roots.clone(), provider.clone())
                .build()
                .unwrap(),
        )
    } else {
        server.with_no_client_auth()
    };
    let server = server
        .with_single_cert(
            vec![server_certificate.into()],
            PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
        )
        .unwrap();
    let peer = WebPkiServerVerifier::builder_with_provider(roots, provider)
        .build()
        .unwrap();
    let (client_io, server_io) = tokio::io::duplex(65536);
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let origin = Origin::parse(host).unwrap();
    let (result, server_result) = tokio::join!(
        connect(
            client_io,
            &origin,
            peer,
            vec![client_certificate.into()],
            &selected,
            relay.clone()
        ),
        acceptor.accept(server_io)
    );
    if result.is_ok() {
        assert!(
            server_result
                .unwrap()
                .get_ref()
                .1
                .peer_certificates()
                .is_some()
        );
    }
    (result.is_ok(), relay.calls.load(Ordering::Acquire))
}

#[tokio::test]
async fn verified_origin_requires_and_uses_exactly_one_valid_client_signature() {
    for version in [&rustls::version::TLS13, &rustls::version::TLS12] {
        assert_eq!(
            handshake(version, "protected.test", true, false).await,
            (true, 1)
        );
        assert_eq!(
            handshake(version, "another.test", true, false).await,
            (false, 0)
        );
        assert_eq!(
            handshake(version, "protected.test", false, false).await,
            (false, 0)
        );
        assert_eq!(
            handshake(version, "protected.test", true, true).await,
            (false, 1)
        );
    }
}
