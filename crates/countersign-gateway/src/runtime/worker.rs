use base64::{Engine, engine::general_purpose::STANDARD};
use countersign_gateway::upstream::{self, SigningRelay};
use countersign_protocol::{
    Origin,
    wire::{GatewayActivation, SignatureScheme as Scheme, TlsVersion},
};
use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg};
use rcgen::{CertificateParams, KeyPair};
use rustls::{
    RootCertStore, ServerConfig, ServerConnection, client::WebPkiServerVerifier,
    crypto::ring::default_provider,
};
use rustls_pki_types::{CertificateDer, CertificateRevocationListDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    io::{IoSlice, IoSliceMut, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::net::{UnixDatagram, UnixStream},
    },
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsAcceptor;

use super::{Result, forward, invalid};

#[derive(Serialize, Deserialize)]
pub struct Start {
    pub origin: Origin,
    pub activation: GatewayActivation,
    pub roots: Vec<String>,
    pub crls: Vec<String>,
}
#[derive(Serialize, Deserialize)]
pub enum CommandMessage {
    Csr(String),
    Sign {
        tls: TlsVersion,
        scheme: Scheme,
        input: String,
    },
    Ready {
        peer_chain: Vec<String>,
    },
}
#[derive(Serialize, Deserialize)]
pub enum Reply {
    Certificates(Vec<String>),
    Signature(String),
    Proceed,
}
const MAX_MESSAGE: usize = 2 * 1024 * 1024;

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > MAX_MESSAGE {
        return Err(invalid("worker IPC exceeds limit"));
    }
    let mut framed = Vec::with_capacity(bytes.len() + 4);
    framed.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    framed.extend_from_slice(&bytes);
    Ok(framed)
}
fn size(header: [u8; 4]) -> Result<usize> {
    let n = u32::from_be_bytes(header) as usize;
    if n > MAX_MESSAGE {
        return Err(invalid("worker IPC exceeds limit"));
    }
    Ok(n)
}
fn read<T: DeserializeOwned>(socket: &mut UnixStream) -> Result<T> {
    let mut header = [0u8; 4];
    socket.read_exact(&mut header)?;
    let mut buf = vec![0; size(header)?];
    socket.read_exact(&mut buf)?;
    Ok(serde_json::from_slice(&buf)?)
}
pub async fn send<T: Serialize>(socket: &mut tokio::net::UnixStream, value: &T) -> Result<()> {
    socket.write_all(&encode(value)?).await?;
    Ok(())
}
pub async fn receive<T: DeserializeOwned>(socket: &mut tokio::net::UnixStream) -> Result<T> {
    let mut header = [0; 4];
    socket.read_exact(&mut header).await?;
    let mut buf = vec![0; size(header)?];
    socket.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

pub struct ChildHandle {
    child: Child,
    control: UnixDatagram,
}
impl Drop for ChildHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl ChildHandle {
    pub fn launch() -> Result<Self> {
        let (control, child_control) = UnixDatagram::pair()?;
        control.set_nonblocking(true)?;
        // Only the executable, public runtime libraries and three standard
        // descriptors enter the sandbox. There is no filesystem path to the
        // CA, Broker credentials, other children, or parent process memory.
        let exe = std::env::current_exe()?;
        let child = Command::new("/usr/bin/bwrap")
            .env_clear()
            .args([
                "--unshare-all",
                "--die-with-parent",
                "--new-session",
                "--cap-drop",
                "ALL",
                "--clearenv",
                "--ro-bind",
                "/lib",
                "/lib",
                "--ro-bind-try",
                "/lib64",
                "/lib64",
                "--ro-bind",
            ])
            .arg(exe)
            .args(["/worker", "--chdir", "/", "--", "/worker", "grant-worker"])
            .stdin(Stdio::from(OwnedFd::from(child_control)))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        Ok(Self { child, control })
    }
    pub fn attach(&mut self) -> Result<[tokio::net::UnixStream; 3]> {
        if self.child.try_wait()?.is_some() {
            return Err(invalid("grant worker exited"));
        }
        let (a, b) = UnixStream::pair()?;
        let (c, d) = UnixStream::pair()?;
        let (e, f) = UnixStream::pair()?;
        let fds = [b.as_raw_fd(), d.as_raw_fd(), f.as_raw_fd()];
        sendmsg::<()>(
            self.control.as_raw_fd(),
            &[IoSlice::new(&[1])],
            &[ControlMessage::ScmRights(&fds)],
            MsgFlags::MSG_NOSIGNAL,
            None,
        )?;
        let stream = |s: UnixStream| -> Result<tokio::net::UnixStream> {
            s.set_nonblocking(true)?;
            Ok(tokio::net::UnixStream::from_std(s)?)
        };
        Ok([stream(a)?, stream(c)?, stream(e)?])
    }
}

pub fn serve() -> Result<()> {
    // No secrets or network sockets are inherited. The authenticated parent
    // delivers three fresh, connected local stream endpoints per connection.
    let active = Arc::new(AtomicUsize::new(0));
    loop {
        let mut byte = [0u8; 1];
        let mut iov = [IoSliceMut::new(&mut byte)];
        let mut space = nix::cmsg_space!([i32; 3]);
        let msg = recvmsg::<()>(0, &mut iov, Some(&mut space), MsgFlags::MSG_CMSG_CLOEXEC)?;
        let mut received = Vec::new();
        for control in msg.cmsgs()? {
            if let ControlMessageOwned::ScmRights(fds) = control {
                for fd in fds {
                    // SAFETY: each SCM_RIGHTS descriptor is freshly allocated to this
                    // process by recvmsg and transferred exactly once here.
                    received.push(unsafe { UnixStream::from_raw_fd(fd) });
                }
            }
        }
        if msg.bytes != 1
            || msg
                .flags
                .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC)
        {
            return Err(invalid("invalid worker dispatch"));
        }
        let [down, up, control]: [UnixStream; 3] = received
            .try_into()
            .map_err(|_| invalid("invalid worker streams"))?;
        if active.load(Ordering::Acquire) >= 32 {
            continue;
        }
        active.fetch_add(1, Ordering::AcqRel);
        let active = active.clone();
        std::thread::Builder::new()
            .name("grant-connection".into())
            .spawn(move || {
                let _ = run(down, up, control);
                active.fetch_sub(1, Ordering::AcqRel);
            })?;
    }
}

struct Relay {
    control: Mutex<UnixStream>,
}
impl SigningRelay for Relay {
    fn sign(
        &self,
        v: rustls::ProtocolVersion,
        s: rustls::SignatureScheme,
        data: &[u8],
    ) -> std::result::Result<Vec<u8>, rustls::Error> {
        use rustls::SignatureScheme::*;
        let deny = || rustls::Error::General("scoped signing unavailable".into());
        let tls = match v {
            rustls::ProtocolVersion::TLSv1_3 => TlsVersion::Tls13,
            rustls::ProtocolVersion::TLSv1_2 => TlsVersion::Tls12,
            _ => return Err(deny()),
        };
        let scheme = match s {
            ECDSA_NISTP256_SHA256 => Scheme::EcdsaNistp256Sha256,
            ECDSA_NISTP384_SHA384 => Scheme::EcdsaNistp384Sha384,
            RSA_PSS_SHA256 => Scheme::RsaPssSha256,
            RSA_PSS_SHA384 => Scheme::RsaPssSha384,
            RSA_PSS_SHA512 => Scheme::RsaPssSha512,
            RSA_PKCS1_SHA256 => Scheme::RsaPkcs1Sha256,
            RSA_PKCS1_SHA384 => Scheme::RsaPkcs1Sha384,
            RSA_PKCS1_SHA512 => Scheme::RsaPkcs1Sha512,
            _ => return Err(deny()),
        };
        let mut control = self.control.lock().map_err(|_| deny())?;
        let bytes = encode(&CommandMessage::Sign {
            tls,
            scheme,
            input: STANDARD.encode(data),
        })
        .map_err(|_| deny())?;
        control.write_all(&bytes).map_err(|_| deny())?;
        match read(&mut control).map_err(|_| deny())? {
            Reply::Signature(text) => STANDARD.decode(text).map_err(|_| deny()),
            _ => Err(deny()),
        }
    }
}
fn run(down: UnixStream, up: UnixStream, mut control: UnixStream) -> Result<()> {
    control.set_read_timeout(Some(Duration::from_secs(120)))?;
    control.set_write_timeout(Some(Duration::from_secs(5)))?;
    let start: Start = read(&mut control)?;
    let key = KeyPair::generate()?;
    let csr =
        CertificateParams::new(vec![start.origin.host().to_owned()])?.serialize_request(&key)?;
    control.write_all(&encode(&CommandMessage::Csr(STANDARD.encode(csr.der())))?)?;
    let Reply::Certificates(certs) = read(&mut control)? else {
        return Err(invalid("invalid issuer response"));
    };
    let certs = certs
        .iter()
        .map(|b| STANDARD.decode(b).map(CertificateDer::from))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let provider = Arc::new(default_provider());
    let mut server = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, PrivatePkcs8KeyDer::from(key.serialize_der()).into())?;
    server.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    server.send_tls13_tickets = 0;
    server.max_early_data_size = 0;
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let mut roots = RootCertStore::empty();
    for root in start.roots {
        roots.add(CertificateDer::from(STANDARD.decode(root)?))?;
    }
    let mut verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider);
    if !start.crls.is_empty() {
        let crls = start
            .crls
            .iter()
            .map(|c| STANDARD.decode(c).map(CertificateRevocationListDer::from))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        verifier = verifier.with_crls(crls).enforce_revocation_expiration();
    }
    let verifier = verifier.build()?;
    let chain = start
        .activation
        .chain
        .as_slice()
        .iter()
        .map(|b| CertificateDer::from(b.as_slice().to_vec()))
        .collect();
    let fp = start
        .activation
        .activation
        .grant
        .cert_sha256
        .as_slice()
        .try_into()?;
    // The current-thread executor belongs to this connection only. A native
    // signing wait cannot starve another connection or the parent lease timers.
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            down.set_nonblocking(true)?;
            up.set_nonblocking(true)?;
            let down = tokio::net::UnixStream::from_std(down)?;
            let up = tokio::net::UnixStream::from_std(up)?;
            let down = TlsAcceptor::from(Arc::new(server)).accept(down).await?;
            let tls: &ServerConnection = down.get_ref().1;
            let name = tls
                .server_name()
                .ok_or_else(|| invalid("missing downstream SNI"))?;
            if name != start.origin.host() {
                return Err(invalid("downstream SNI mismatch"));
            }
            let down_h2 = tls.alpn_protocol() == Some(b"h2");
            let relay = Arc::new(Relay {
                control: Mutex::new(control.try_clone()?),
            });
            let up = upstream::connect(up, &start.origin, verifier, chain, fp, relay).await?;
            let up_h2 = up.get_ref().1.alpn_protocol() == Some(b"h2");
            let peer_chain = up
                .get_ref()
                .1
                .peer_certificates()
                .ok_or_else(|| invalid("missing peer chain"))?
                .iter()
                .map(|cert| STANDARD.encode(cert))
                .collect();
            control.write_all(&encode(&CommandMessage::Ready { peer_chain })?)?;
            let Reply::Proceed = read(&mut control)? else {
                return Err(invalid("connection admission refused"));
            };
            forward::http(down, down_h2, up, up_h2, start.origin).await
        })
}
