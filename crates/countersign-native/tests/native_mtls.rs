//! Drive the production JS addon over two real, in-memory rustls handshakes.
//! The CI driver starts each test after it provisions three native identities.
use base64::{Engine, engine::general_purpose::STANDARD};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::sign::{CertifiedKey, Signer, SigningKey, SingleCertAndKey};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection,
    SignatureAlgorithm, SignatureScheme,
};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};

#[derive(Debug)]
struct Channel {
    io: Mutex<(ChildStdin, BufReader<ChildStdout>)>,
    tls: &'static str,
}
#[derive(Debug)]
struct Key(Arc<Channel>);
impl SigningKey for Key {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ECDSA_NISTP256_SHA256)
            .then(|| Box::new(Key(self.0.clone())) as Box<dyn Signer>)
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}
impl Signer for Key {
    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let mut pair = self.0.io.lock().unwrap();
        let (input, out) = &mut *pair;
        writeln!(
            input,
            "{}",
            json!({"data":STANDARD.encode(message),"tls":self.0.tls})
        )
        .unwrap();
        input.flush().unwrap();
        let mut line = String::new();
        out.read_line(&mut line).unwrap();
        let result: Value = serde_json::from_str(&line)
            .map_err(|_| rustls::Error::General("native signing failed".into()))?;
        STANDARD
            .decode(result["signature"].as_str().unwrap())
            .map_err(|_| rustls::Error::General("invalid signature".into()))
    }
}

#[test]
#[ignore = "native CI driver provisions a disposable OS provider before this test"]
fn native_client_certificate_verify() {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = std::fs::read(std::env::var("COUNTERSIGN_CI_CLIENT_ROOT").unwrap()).unwrap();
    for (name, version) in [
        ("tls13", &rustls::version::TLS13),
        ("tls12", &rustls::version::TLS12),
    ] {
        let mut peer = Command::new("node")
            .arg(base.join("tests/native-peer.cjs"))
            .env(
                "COUNTERSIGN_CI_PICKER_COUNT",
                if name == "tls12" { "2" } else { "3" },
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut out = BufReader::new(peer.stdout.take().unwrap());
        let mut line = String::new();
        out.read_line(&mut line).unwrap();
        let hello: Value =
            serde_json::from_str(&line).expect("addon must resolve preinstalled identities");
        let chain: Vec<CertificateDer<'static>> = hello["chain"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| CertificateDer::from(STANDARD.decode(v.as_str().unwrap()).unwrap()))
            .collect();
        let public_leaf = chain[0].clone();
        let client_key = CertifiedKey::new(
            chain,
            Arc::new(Key(Arc::new(Channel {
                io: Mutex::new((peer.stdin.take().unwrap(), out)),
                tls: name,
            }))),
        );
        let server = rcgen::generate_simple_self_signed(vec!["mtls.example".into()]).unwrap();
        let mut trust = RootCertStore::empty();
        trust.add(server.cert.der().clone()).unwrap();
        let cfg = ClientConfig::builder_with_protocol_versions(&[version])
            .with_root_certificates(trust)
            .with_client_cert_resolver(Arc::new(SingleCertAndKey::from(client_key)));
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(root.clone())).unwrap();
        let cfg_server = ServerConfig::builder_with_protocol_versions(&[version])
            .with_client_cert_verifier(
                WebPkiClientVerifier::builder(Arc::new(roots))
                    .build()
                    .unwrap(),
            )
            .with_single_cert(
                vec![server.cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server.signing_key.serialize_der())),
            )
            .unwrap();
        let mut client =
            ClientConnection::new(Arc::new(cfg), "mtls.example".try_into().unwrap()).unwrap();
        let mut server = ServerConnection::new(Arc::new(cfg_server)).unwrap();
        client.writer().write_all(b"ok").unwrap();
        for _ in 0..16 {
            let mut bytes = Vec::new();
            client.write_tls(&mut bytes).unwrap();
            server.read_tls(&mut bytes.as_slice()).unwrap();
            server.process_new_packets().unwrap();
            let mut bytes = Vec::new();
            server.write_tls(&mut bytes).unwrap();
            client.read_tls(&mut bytes.as_slice()).unwrap();
            client.process_new_packets().unwrap();
            if !client.is_handshaking() && !server.is_handshaking() && !client.wants_write() {
                break;
            }
        }
        assert_eq!(server.peer_certificates().unwrap()[0], public_leaf);
        let mut msg = [0; 2];
        server.reader().read_exact(&mut msg).unwrap();
        assert_eq!(&msg, b"ok");
        drop(client);
        assert!(peer.wait().unwrap().success());
    }
}
