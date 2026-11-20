use base64::{Engine, engine::general_purpose::STANDARD};
use countersign_gateway::{
    upstream::{self, SigningRelay},
    worker_sandbox::{Landlock, Layer, Layers},
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
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsAcceptor;

use super::{Result, config::WorkerSandbox, forward, invalid};

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

/// The command that starts a grant worker under the chosen worker sandbox.
/// Either way it gets a cleared environment, and it confines itself with the
/// base layers once it runs.
fn sandbox(sandbox: WorkerSandbox, executable: &std::path::Path) -> Command {
    match sandbox {
        WorkerSandbox::Namespaces => namespaces(executable),
        WorkerSandbox::Filter => direct(executable),
    }
}

/// The filter sandbox: the supervisor starts the grant worker itself.
fn direct(executable: &std::path::Path) -> Command {
    use std::os::unix::process::CommandExt;
    let mut command = Command::new(executable);
    command.env_clear();
    let supervisor = std::process::id() as nix::libc::pid_t;
    // SAFETY: the closure runs between fork and exec, and makes only system
    // calls: no allocation, no locks.
    unsafe {
        command.pre_exec(move || {
            use nix::libc;
            let check = |result: libc::c_long| match result {
                -1 => Err(std::io::Error::last_os_error()),
                _ => Ok(()),
            };
            // What bubblewrap's --die-with-parent does under the namespace
            // sandbox: a grant worker does not outlive its supervisor, whose
            // end it would not see on its control socket. The supervisor may
            // have ended before the request took effect.
            check(libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL).into())?;
            if libc::getppid() != supervisor {
                return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
            }
            // Only the control socket and the standard streams stay open
            // across the exec, whatever the supervisor itself inherited.
            // Marked and not closed here: the standard library reports a
            // failed exec over a descriptor of its own.
            // CLOSE_RANGE_CLOEXEC needs Linux 5.11; an older kernel
            // refuses, and so the launch fails.
            check(libc::syscall(
                libc::SYS_close_range,
                3 as libc::c_uint,
                libc::c_uint::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            ))
        });
    }
    command
}

/// The namespace sandbox: only public runtime libraries and the executable
/// enter this grant's new mount, PID and network namespaces. Each inherited
/// stream is private IPC.
fn namespaces(executable: &std::path::Path) -> Command {
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

/// Why the startup probe failed: the chosen worker sandbox and, in `reason`,
/// the layer that failed and its cause. It names no other sandbox: the
/// operator reads the trade-off before choosing one (ADR 0001, decision 4).
#[derive(Debug, thiserror::Error)]
#[error(
    "worker sandbox \"{sandbox}\" failed: {reason}\nSee \"Choose a worker sandbox\" in the operator guide: https://zeroae.github.io/countersign/operate/#choose-a-worker-sandbox"
)]
pub struct SandboxError {
    sandbox: WorkerSandbox,
    reason: String,
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

/// The startup probe's report of a grant worker's layers, in one byte: the
/// Landlock ABI, or 0 for none.
fn report(layers: Layers) -> [u8; 1] {
    match layers.landlock {
        Landlock::Unavailable => [0],
        Landlock::Abi(abi) => [abi],
    }
}
fn reported(report: [u8; 1]) -> Layers {
    Layers {
        landlock: match report {
            [0] => Landlock::Unavailable,
            [abi] => Landlock::Abi(abi),
        },
    }
}

pub struct ChildHandle {
    control: UnixDatagram,
    /// Dropping this stops the grant worker.
    _stop: tokio::sync::oneshot::Sender<()>,
}
impl ChildHandle {
    fn start(
        sandbox: WorkerSandbox,
        stderr: Stdio,
    ) -> Result<(tokio::process::Child, UnixDatagram)> {
        let (control, child_control) = UnixDatagram::pair()?;
        control.set_nonblocking(true)?;
        let process =
            tokio::process::Command::from(self::sandbox(sandbox, &std::env::current_exe()?))
                .kill_on_drop(true)
                .arg("grant-worker")
                .stdin(Stdio::from(OwnedFd::from(child_control)))
                .stdout(Stdio::null())
                .stderr(stderr)
                .spawn()?;
        Ok((process, control))
    }

    pub fn launch(sandbox: WorkerSandbox) -> Result<(Self, Exit)> {
        let (mut process, control) = Self::start(sandbox, Stdio::null())?;
        let (stop, mut stopped) = tokio::sync::oneshot::channel::<()>();
        let (report, exit) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            tokio::select! {
                status = process.wait() => {
                    if let Ok(status) = status {
                        let _ = report.send(status);
                    }
                }
                _ = &mut stopped => {
                    let _ = process.kill().await;
                }
            }
        });
        Ok((
            Self {
                control,
                _stop: stop,
            },
            exit,
        ))
    }

    /// Check the chosen worker sandbox, the executable and the control socket
    /// at startup. This short-lived worker receives no grant, credentials or
    /// traffic. It confines itself as every grant worker does and reports its
    /// layers.
    pub async fn verify_environment(
        sandbox: WorkerSandbox,
    ) -> std::result::Result<Layers, SandboxError> {
        // What the supervisor adds around the base layers. A failure that is
        // not a base layer's is this one's.
        let outer = match sandbox {
            WorkerSandbox::Namespaces => "namespaces",
            WorkerSandbox::Filter => "launch",
        };
        Self::probe(sandbox).await.map_err(|reason| SandboxError {
            sandbox,
            reason: if [Layer::NonDumpable, Layer::Landlock, Layer::AllowList]
                .iter()
                .any(|layer| reason.starts_with(&format!("{layer}: ")))
            {
                reason
            } else {
                format!("{outer}: {reason}")
            },
        })
    }

    /// The probe's layers, or why it failed. A grant worker that could not
    /// confine itself names the base layer first (`runtime::grant_worker`).
    async fn probe(sandbox: WorkerSandbox) -> std::result::Result<Layers, String> {
        let (process, control) =
            Self::start(sandbox, Stdio::piped()).map_err(|error| error.to_string())?;
        control.send(&[0]).map_err(|error| error.to_string())?;
        let output = tokio::time::timeout(Duration::from_secs(5), process.wait_with_output())
            .await
            .map_err(|_| "the probe grant worker did not finish in 5 seconds".to_owned())?
            .map_err(|error| error.to_string())?;
        if killed_by_filter(output.status) {
            return Err(format!(
                "{}: the filter killed the probe grant worker (SIGSYS)",
                Layer::AllowList
            ));
        }
        if !output.status.success() {
            let hint: String = String::from_utf8_lossy(&output.stderr)
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .chars()
                .take(512)
                .collect();
            return Err(if hint.is_empty() {
                format!("the probe grant worker ended with {}", output.status)
            } else {
                hint
            });
        }
        // The report was queued before the probe exited.
        let mut message = [0u8; 2];
        match control.recv(&mut message) {
            Ok(1) => Ok(reported([message[0]])),
            _ => Err("the probe grant worker reported no layers".to_owned()),
        }
    }

    pub fn attach(&mut self) -> Result<[tokio::net::UnixStream; 3]> {
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
            // The startup probe. It reports this grant worker's layers from
            // where a connection is served, a thread with an async runtime, so
            // a host that the allow-list cannot serve on fails at startup.
            return std::thread::spawn(move || -> Result<()> {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                nix::unistd::write(std::io::stdin(), &report(layers))?;
                Ok(())
            })
            .join()
            .map_err(|_| invalid("worker sandbox probe panicked"))?;
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
    fn filter_sandbox_launch_passes_on_no_descriptor_and_no_environment() {
        // A descriptor the supervisor inherited open across exec, as `dup`
        // leaves it, and a variable of the supervisor's environment.
        // SAFETY: `dup` takes a descriptor number and returns a new one, closed below.
        let inherited = unsafe { nix::libc::dup(0) };
        assert!(inherited > 2);
        assert!(std::env::var_os("HOME").is_some());
        // sh stands in for the grant worker, started as the supervisor starts one.
        let result = direct(Path::new("/bin/sh"))
            .args([
                "-c",
                r#"test -e /proc/self/fd/0 && test ! -e /proc/self/fd/"$1" && test -z "${HOME+set}""#,
                "probe",
            ])
            .arg(inherited.to_string())
            .output()
            .unwrap();
        // SAFETY: closes the descriptor `dup` returned above, once.
        unsafe { nix::libc::close(inherited) };
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    #[test]
    fn worker_namespace_excludes_parent_files_and_parent_network() {
        let marker =
            std::env::temp_dir().join(format!("countersign-isolation-{}", uuid::Uuid::new_v4()));
        fs::write(&marker, b"private sentinel").unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port().to_string();
        // Use bash only as the test executable, under the same namespace
        // and mount configuration as a production grant worker.
        let result=namespaces(Path::new("/bin/bash"))
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
