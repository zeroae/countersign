use base64::{Engine, engine::general_purpose::STANDARD};
use countersign_gateway::{
    upstream::{self, SigningRelay},
    worker_sandbox::{Landlock, Layers},
};
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
        unix::{
            net::{UnixDatagram, UnixStream},
            process::ExitStatusExt,
        },
    },
    process::{Command, ExitStatus, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
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
    UpstreamResponse,
    OpenStream(u64),
    CloseStream(u64),
    Csr(String),
    Sign {
        tls: TlsVersion,
        scheme: Scheme,
        input: String,
        peer_chain: Vec<String>,
    },
    Ready,
}
#[derive(Serialize, Deserialize)]
pub enum Reply {
    StreamGranted(bool),
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

/// Only public runtime libraries and the executable enter this grant's new
/// mount, PID and network namespaces. Each inherited stream is private IPC.
fn sandbox(executable: &std::path::Path) -> Command {
    let mut command = Command::new("/usr/bin/bwrap");
    command
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
        .arg(executable)
        .args(["/worker", "--chdir", "/", "--", "/worker"]);
    command
}

/// Resolves with a grant worker's exit status when it ends on its own, and
/// with an error when the supervisor stopped it.
pub type Exit = tokio::sync::oneshot::Receiver<ExitStatus>;

/// Whether the seccomp allow-list killed this grant worker. bubblewrap, which
/// the supervisor waits on under the namespace sandbox, reports its child's
/// fatal signal as an exit code of 128 plus the signal (measured with
/// bubblewrap 0.9.0 on 2026-11-19: `bwrap ... sh -c 'kill -SYS $$'` exits 159).
pub fn killed_by_filter(status: ExitStatus) -> bool {
    let sigsys = nix::libc::SIGSYS;
    status.signal() == Some(sigsys) || status.code() == Some(128 + sigsys)
}

pub struct ChildHandle {
    control: UnixDatagram,
    exited: Arc<AtomicBool>,
    /// Dropping this stops the grant worker.
    _stop: tokio::sync::oneshot::Sender<()>,
}
impl ChildHandle {
    fn start(stderr: Stdio) -> Result<(tokio::process::Child, UnixDatagram)> {
        let (control, child_control) = UnixDatagram::pair()?;
        control.set_nonblocking(true)?;
        let child = tokio::process::Command::from(sandbox(&std::env::current_exe()?))
            .kill_on_drop(true)
            .arg("grant-worker")
            .stdin(Stdio::from(OwnedFd::from(child_control)))
            .stdout(Stdio::null())
            .stderr(stderr)
            .spawn()?;
        Ok((child, control))
    }

    pub fn launch() -> Result<(Self, Exit)> {
        let (mut child, control) = Self::start(Stdio::null())?;
        let exited = Arc::new(AtomicBool::new(false));
        let (stop, mut stopped) = tokio::sync::oneshot::channel::<()>();
        let (report, exit) = tokio::sync::oneshot::channel();
        let flag = exited.clone();
        tokio::spawn(async move {
            tokio::select! {
                status = child.wait() => {
                    flag.store(true, Ordering::Release);
                    if let Ok(status) = status {
                        let _ = report.send(status);
                    }
                }
                _ = &mut stopped => {
                    let _ = child.kill().await;
                }
            }
        });
        Ok((
            Self {
                control,
                exited,
                _stop: stop,
            },
            exit,
        ))
    }

    /// Check the actual host sandbox, executable and control socket at startup.
    /// This short-lived worker receives no grant, credentials or traffic. It
    /// confines itself as every grant worker does and reports its layers.
    pub async fn verify_environment() -> Result<Layers> {
        let (child, control) = Self::start(Stdio::piped())?;
        control.send(&[0])?;
        let output =
            tokio::time::timeout(Duration::from_secs(5), child.wait_with_output()).await??;
        if !output.status.success() {
            let hint: String = String::from_utf8_lossy(&output.stderr)
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .chars()
                .take(512)
                .collect();
            return Err(std::io::Error::other(format!(
                "Gateway worker sandbox failed to start ({}): {hint}",
                output.status
            ))
            .into());
        }
        // The report was queued before the probe exited.
        let mut report = [0u8; 2];
        match control.recv(&mut report) {
            Ok(1) => Ok(Layers {
                landlock: match report[0] {
                    0 => Landlock::Unavailable,
                    abi => Landlock::Abi(abi),
                },
            }),
            _ => Err(invalid("grant worker reported no worker sandbox layers")),
        }
    }

    pub fn attach(&mut self) -> Result<[tokio::net::UnixStream; 3]> {
        if self.exited.load(Ordering::Acquire) {
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

pub fn serve(layers: Layers) -> Result<()> {
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
        if byte == [0] && received.is_empty() {
            // The startup probe: report the layers this grant worker runs under.
            let report = match layers.landlock {
                Landlock::Unavailable => 0,
                Landlock::Abi(abi) => abi,
            };
            nix::unistd::write(std::io::stdin(), &[report])?;
            return Ok(());
        }
        if byte != [1] {
            return Err(invalid("invalid worker control command"));
        }
        let [down, up, control]: [UnixStream; 3] = received
            .try_into()
            .map_err(|_| invalid("invalid worker streams"))?;
        if active.load(Ordering::Acquire) >= 32 {
            continue;
        }
        active.fetch_add(1, Ordering::AcqRel);
        let active = active.clone();
        // Unnamed: naming a thread is one more system call to allow.
        std::thread::Builder::new().spawn(move || {
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
        peer_chain: &[CertificateDer<'static>],
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
            peer_chain: peer_chain
                .iter()
                .map(|cert| STANDARD.encode(cert))
                .collect(),
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
            control.write_all(&encode(&CommandMessage::Ready)?)?;
            let Reply::Proceed = read(&mut control)? else {
                return Err(invalid("connection admission refused"));
            };
            let limits = Arc::new(StreamLimits {
                control: Mutex::new(control),
                next: std::sync::atomic::AtomicU64::new(1),
                upstream_response: std::sync::atomic::AtomicBool::new(false),
            });
            forward::http(down, down_h2, up, up_h2, start.origin, limits).await
        })
}

/// These short IPC exchanges execute on the thread dedicated to this TLS pair.
/// The supervisor owns request quotas across concurrent HTTP/2 connections.
pub struct StreamLimits {
    control: Mutex<UnixStream>,
    next: std::sync::atomic::AtomicU64,
    upstream_response: std::sync::atomic::AtomicBool,
}
pub struct StreamPermit {
    limits: Arc<StreamLimits>,
    id: u64,
}
impl StreamLimits {
    pub fn observed_response(&self) {
        if !self.upstream_response.swap(true, Ordering::Relaxed)
            && let Ok(mut control) = self.control.lock()
            && let Ok(frame) = encode(&CommandMessage::UpstreamResponse)
        {
            let _ = control.write_all(&frame);
        }
    }
    pub fn acquire(self: &Arc<Self>) -> Result<Option<StreamPermit>> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        if id == 0 {
            return Err(invalid("request counter exhausted"));
        }
        let mut control = self
            .control
            .lock()
            .map_err(|_| invalid("worker control unavailable"))?;
        control.write_all(&encode(&CommandMessage::OpenStream(id))?)?;
        match read(&mut control)? {
            Reply::StreamGranted(true) => Ok(Some(StreamPermit {
                limits: self.clone(),
                id,
            })),
            Reply::StreamGranted(false) => Ok(None),
            _ => Err(invalid("unexpected request admission response")),
        }
    }
}
impl Drop for StreamPermit {
    fn drop(&mut self) {
        if let (Ok(mut control), Ok(request)) = (
            self.limits.control.lock(),
            encode(&CommandMessage::CloseStream(self.id)),
        ) {
            let _ = control.write_all(&request);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, net::TcpListener, path::Path};
    #[test]
    fn worker_namespace_excludes_parent_files_and_parent_network() {
        let marker =
            std::env::temp_dir().join(format!("countersign-isolation-{}", uuid::Uuid::new_v4()));
        fs::write(&marker, b"private sentinel").unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port().to_string();
        // Use bash only as the test executable, under the same namespace
        // and mount configuration as a production grant worker.
        let result=sandbox(Path::new("/bin/bash"))
            .args(["-c", r#"test ! -e "$1" && test ! -e /proc/1/mem && ! (echo probe > /dev/tcp/127.0.0.1/"$2")"#,"probe"])
            .arg(&marker).arg(port).output();
        fs::remove_file(marker).unwrap();
        let result = result.unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        listener.set_nonblocking(true).unwrap();
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}
