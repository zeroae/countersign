//! PROTOTYPE, throwaway, never merge. Issue #18.
//!
//! Question: on a host that refuses nested namespaces (ECS Fargate 1.4.0), which
//! grant-worker isolation mechanisms can an unprivileged Gateway still apply, and
//! does each one block what the per-grant isolation contract requires?
//!
//! For each mechanism it forks a stand-in "worker", confines it, hands it a stream
//! by SCM_RIGHTS exactly as the Gateway does, then tries what a compromised worker
//! would try. Output is Markdown, ready to paste into the issue.
//!
//! The seccomp filter here is a deny-list for probing only. A real design would be
//! an allow-list.

use std::ffi::CString;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::process::Command;

/// Stands in for supervisor secrets. Forked children share its address.
static SECRET: [u8; 16] = *b"supervisor-only!";

fn last() -> std::io::Error {
    std::io::Error::last_os_error()
}

fn errno() -> i32 {
    last().raw_os_error().unwrap_or(0)
}

fn read_trim(path: &str) -> String {
    std::fs::read_to_string(path)
        .map(|s| s.trim().replace('\n', " "))
        .unwrap_or_else(|e| format!("unreadable ({e})"))
}

fn status_field(field: &str) -> String {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with(&format!("{field}:")))
                .map(|l| l[field.len() + 1..].trim().to_string())
        })
        .unwrap_or_else(|| "?".into())
}

// ---------- fd passing, as the Gateway's worker handoff does ----------

fn send_fd(sock: RawFd, fd: RawFd) -> std::io::Result<()> {
    unsafe {
        let mut byte = [b'f'];
        let mut iov = libc::iovec { iov_base: byte.as_mut_ptr().cast(), iov_len: 1 };
        let space = libc::CMSG_SPACE(size_of::<RawFd>() as u32) as usize;
        let mut cbuf = vec![0u8; space];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr().cast();
        msg.msg_controllen = space as _;
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as u32) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>(), fd);
        if libc::sendmsg(sock, &msg, 0) < 0 {
            return Err(last());
        }
    }
    Ok(())
}

fn recv_fd(sock: RawFd) -> std::io::Result<OwnedFd> {
    unsafe {
        let mut byte = [0u8];
        let mut iov = libc::iovec { iov_base: byte.as_mut_ptr().cast(), iov_len: 1 };
        let space = libc::CMSG_SPACE(size_of::<RawFd>() as u32) as usize;
        let mut cbuf = vec![0u8; space];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr().cast();
        msg.msg_controllen = space as _;
        if libc::recvmsg(sock, &mut msg, 0) <= 0 {
            return Err(last());
        }
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() || (*cmsg).cmsg_type != libc::SCM_RIGHTS {
            return Err(std::io::Error::other("no SCM_RIGHTS in message"));
        }
        Ok(OwnedFd::from_raw_fd(std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>())))
    }
}

// ---------- confinement mechanisms ----------

fn no_new_privs() -> Result<(), String> {
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(format!("PR_SET_NO_NEW_PRIVS: {}", last()));
    }
    Ok(())
}

fn seccomp() -> Result<String, String> {
    const RET_ALLOW: u32 = 0x7fff_0000;
    const RET_ERRNO: u32 = 0x0005_0000;
    const RET_KILL_PROCESS: u32 = 0x8000_0000;
    const LD_ABS_W: u16 = 0x20;
    const JEQ_K: u16 = 0x15;
    const RET_K: u16 = 0x06;
    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 0xC000_003E;
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 0xC000_00B7;

    let mut denied: Vec<(u16, u32)> = Vec::new();
    // x32 syscalls on x86_64 would bypass a numbered deny-list.
    #[cfg(target_arch = "x86_64")]
    denied.push((0x35 /* JGE_K */, 0x4000_0000));
    #[cfg(target_arch = "x86_64")]
    for nr in [libc::SYS_open, libc::SYS_creat] {
        denied.push((JEQ_K, nr as u32));
    }
    for nr in [
        libc::SYS_openat,
        libc::SYS_openat2,
        libc::SYS_open_by_handle_at,
        libc::SYS_socket,
        libc::SYS_connect,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
    ] {
        denied.push((JEQ_K, nr as u32));
    }

    let f = |code, k, jt, jf| libc::sock_filter { code, jt, jf, k };
    let mut prog = vec![
        f(LD_ABS_W, 4, 0, 0), // seccomp_data.arch
        f(JEQ_K, ARCH, 1, 0),
        f(RET_K, RET_KILL_PROCESS, 0, 0),
        f(LD_ABS_W, 0, 0, 0), // seccomp_data.nr
    ];
    let n = denied.len();
    for (i, (code, k)) in denied.into_iter().enumerate() {
        prog.push(f(code, k, (n - i) as u8, 0)); // match: jump past ALLOW to ERRNO
    }
    prog.push(f(RET_K, RET_ALLOW, 0, 0));
    prog.push(f(RET_K, RET_ERRNO | libc::EPERM as u32, 0, 0));

    let fprog = libc::sock_fprog { len: prog.len() as u16, filter: prog.as_mut_ptr() };
    no_new_privs()?;
    if unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &fprog) } != 0 {
        return Err(format!("PR_SET_SECCOMP: {}", last()));
    }
    Ok("deny-list filter installed".into())
}

const LANDLOCK_CREATE_RULESET: libc::c_long = 444; // same number on x86_64 and aarch64
const LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

fn landlock_abi() -> Result<i64, String> {
    let r = unsafe {
        libc::syscall(LANDLOCK_CREATE_RULESET, std::ptr::null::<u8>(), 0usize, 1u32 /* VERSION */)
    };
    if r < 0 { Err(last().to_string()) } else { Ok(r) }
}

#[repr(C)]
struct RulesetAttr {
    fs: u64,
    net: u64,
    scoped: u64,
}

/// Handles every access right this kernel's ABI knows and grants none: no file
/// access, no TCP bind/connect (ABI 4+), no abstract-socket or signal reach
/// outside the domain (ABI 6+).
fn landlock() -> Result<String, String> {
    let abi = landlock_abi()?;
    let attr = RulesetAttr {
        fs: match abi {
            1 => 0x1fff,
            2 => 0x3fff,
            3 | 4 => 0x7fff,
            _ => 0xffff,
        },
        net: if abi >= 4 { 0b11 } else { 0 },
        scoped: if abi >= 6 { 0b11 } else { 0 },
    };
    let size: usize = if abi < 4 { 8 } else if abi < 6 { 16 } else { 24 };
    let fd = unsafe { libc::syscall(LANDLOCK_CREATE_RULESET, &attr, size, 0u32) };
    if fd < 0 {
        return Err(format!("create_ruleset: {}", last()));
    }
    no_new_privs()?;
    if unsafe { libc::syscall(LANDLOCK_RESTRICT_SELF, fd, 0u32) } != 0 {
        return Err(format!("restrict_self: {}", last()));
    }
    unsafe { libc::close(fd as i32) };
    Ok(format!("ABI v{abi}"))
}

// ---------- what a compromised worker tries ----------

struct Check {
    name: &'static str,
    /// Some(detail) when the attempt got through.
    got_through: Option<String>,
    denied_detail: String,
    must_work: bool,
}

fn attempt(name: &'static str, must_work: bool, r: Result<String, i32>) -> Check {
    match r {
        Ok(d) => Check { name, got_through: Some(d), denied_detail: String::new(), must_work },
        Err(e) if e == libc::EPERM || e == libc::EACCES => Check {
            name,
            got_through: None,
            denied_detail: std::io::Error::from_raw_os_error(e).to_string(),
            must_work,
        },
        // Any other error means the kernel acted on the request.
        Err(e) => Check {
            name,
            got_through: Some(format!("reached kernel: {}", std::io::Error::from_raw_os_error(e))),
            denied_detail: String::new(),
            must_work,
        },
    }
}

fn try_open(path: &str) -> Result<String, i32> {
    let c = CString::new(path).unwrap();
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 { return Err(errno()) }
    let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut buf = Vec::new();
    let _ = f.read_to_end(&mut buf);
    Ok(format!("read {} bytes", buf.len()))
}

fn try_tcp() -> Result<String, i32> {
    unsafe {
        let s = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if s < 0 { return Err(errno()) }
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as _,
            sin_port: 1u16.to_be(),
            sin_addr: libc::in_addr { s_addr: u32::from_be_bytes([127, 0, 0, 1]).to_be() },
            sin_zero: [0; 8],
        };
        let r = libc::connect(s, (&addr as *const libc::sockaddr_in).cast(), size_of::<libc::sockaddr_in>() as _);
        let e = errno();
        libc::close(s);
        if r == 0 { Ok("connected".into()) } else { Err(e) }
    }
}

fn try_udp() -> Result<String, i32> {
    unsafe {
        let s = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if s < 0 { return Err(errno()) }
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as _,
            sin_port: 9u16.to_be(),
            sin_addr: libc::in_addr { s_addr: u32::from_be_bytes([192, 0, 2, 1]).to_be() },
            sin_zero: [0; 8],
        };
        let r = libc::sendto(s, b"x".as_ptr().cast(), 1, 0, (&addr as *const libc::sockaddr_in).cast(), size_of::<libc::sockaddr_in>() as _);
        let e = errno();
        libc::close(s);
        if r >= 0 { Ok("datagram sent".into()) } else { Err(e) }
    }
}

fn try_exec() -> Result<String, i32> {
    let path = CString::new("/bin/true").unwrap();
    let argv = [path.as_ptr(), std::ptr::null()];
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            libc::execv(path.as_ptr(), argv.as_ptr());
            libc::_exit(100 + errno());
        }
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        match libc::WEXITSTATUS(status) {
            0 => Ok("/bin/true ran".into()),
            c if c > 100 => Err(c - 100),
            c => Ok(format!("exit {c}")),
        }
    }
}

fn try_read_memory(pid: libc::pid_t) -> Result<String, i32> {
    let mut buf = [0u8; 16];
    let local = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: 16 };
    let remote = libc::iovec { iov_base: SECRET.as_ptr() as *mut _, iov_len: 16 };
    let r = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
    if r < 0 { Err(errno()) } else { Ok(format!("read {:?}", String::from_utf8_lossy(&buf[..r as usize]))) }
}

fn checks(ctrl: &UnixStream, supervisor: libc::pid_t, dumpable: libc::pid_t, undumpable: libc::pid_t) -> Vec<Check> {
    let stream = recv_fd(ctrl.as_raw_fd()).map_err(|e| e.raw_os_error().unwrap_or(0)).and_then(|fd| {
        let mut s = String::new();
        std::fs::File::from(fd).read_to_string(&mut s).map_err(|e| e.raw_os_error().unwrap_or(0))?;
        Ok(format!("got {s:?}"))
    });
    let environ = format!("/proc/{supervisor}/environ");
    vec![
        attempt("Receive its streams by SCM_RIGHTS", true, stream),
        attempt("Open a file (/etc/hostname)", false, try_open("/etc/hostname")),
        attempt("Read the supervisor's environment", false, try_open(&environ)),
        attempt("Open a TCP connection", false, try_tcp()),
        attempt("Send a UDP datagram", false, try_udp()),
        attempt("Execute a program", false, try_exec()),
        attempt("Read supervisor memory", false, try_read_memory(supervisor)),
        attempt("Read another worker's memory (dumpable)", false, try_read_memory(dumpable)),
        attempt("Read another worker's memory (non-dumpable)", false, try_read_memory(undumpable)),
    ]
}

// ---------- harness ----------

fn sibling(dumpable: bool) -> libc::pid_t {
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            if !dumpable {
                libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
            }
            loop {
                libc::pause();
            }
        }
        pid
    }
}

type Confine = fn() -> Result<String, String>;

/// Fork a worker, confine it, hand it a stream, collect what got through.
fn run(confine: &[Confine], dumpable: libc::pid_t, undumpable: libc::pid_t) -> Result<(String, Vec<(String, Option<String>, String, bool)>), String> {
    let supervisor = unsafe { libc::getpid() };
    let (mut parent, child) = UnixStream::pair().map_err(|e| e.to_string())?;
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        drop(parent);
        let mut child = child;
        let mut how = Vec::new();
        let mut ok = true;
        for c in confine {
            match c() {
                Ok(d) => how.push(d),
                Err(e) => {
                    how.push(format!("FAILED: {e}"));
                    ok = false;
                }
            }
        }
        let _ = writeln!(child, "{}", how.join("; "));
        if ok {
            for c in checks(&child, supervisor, dumpable, undumpable) {
                let through = c.got_through.unwrap_or_default();
                let _ = writeln!(child, "{}\t{}\t{}\t{}", c.name, through, c.denied_detail, c.must_work);
            }
        }
        unsafe { libc::_exit(0) };
    }
    drop(child);
    // The stream the worker must still be able to receive after confinement.
    let mut fds = [0; 2];
    unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    unsafe { libc::write(fds[1], b"stream-ok".as_ptr().cast(), 9) };
    unsafe { libc::close(fds[1]) };
    let mut out = String::new();
    // The confinement line arrives first; send the stream once it has.
    let mut first = [0u8; 1];
    while parent.read(&mut first).map_err(|e| e.to_string())? == 1 {
        out.push(first[0] as char);
        if first[0] == b'\n' {
            break;
        }
    }
    let _ = send_fd(parent.as_raw_fd(), fds[0]);
    unsafe { libc::close(fds[0]) };
    parent.read_to_string(&mut out).map_err(|e| e.to_string())?;
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    if libc::WIFSIGNALED(status) {
        out.push_str(&format!("\n(worker killed by signal {})", libc::WTERMSIG(status)));
    }
    let mut lines = out.lines();
    let how = lines.next().unwrap_or("(no output)").to_string();
    let rows = lines
        .filter_map(|l| {
            let p: Vec<&str> = l.split('\t').collect();
            (p.len() == 4).then(|| {
                let through = (!p[1].is_empty()).then(|| p[1].to_string());
                (p[0].to_string(), through, p[2].to_string(), p[3] == "true")
            })
        })
        .collect();
    Ok((how, rows))
}

fn host_facts() {
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    unsafe { libc::uname(&mut u) };
    let s = |a: &[libc::c_char]| unsafe { std::ffi::CStr::from_ptr(a.as_ptr()) }.to_string_lossy().into_owned();
    println!("## Host\n");
    println!("| Fact | Value |\n|---|---|");
    println!("| Kernel | {} {} |", s(&u.release), s(&u.machine));
    println!("| uid / gid | {} / {} |", unsafe { libc::getuid() }, unsafe { libc::getgid() });
    for f in ["CapEff", "CapBnd", "NoNewPrivs", "Seccomp", "Seccomp_filters"] {
        println!("| {f} | {} |", status_field(f));
    }
    println!("| LSMs | {} |", read_trim("/sys/kernel/security/lsm"));
    println!("| max_user_namespaces | {} |", read_trim("/proc/sys/user/max_user_namespaces"));
    println!("| Yama ptrace_scope | {} |", read_trim("/proc/sys/kernel/yama/ptrace_scope"));
    println!("| Landlock | {} |", landlock_abi().map(|v| format!("ABI v{v}")).unwrap_or_else(|e| format!("unavailable: {e}")));

    let userns = unsafe {
        let pid = libc::fork();
        if pid == 0 {
            libc::_exit(if libc::unshare(libc::CLONE_NEWUSER) == 0 { 0 } else { errno() });
        }
        let mut st = 0;
        libc::waitpid(pid, &mut st, 0);
        libc::WEXITSTATUS(st)
    };
    println!(
        "| Unprivileged user namespace | {} |",
        if userns == 0 { "allowed".into() } else { format!("refused: {}", std::io::Error::from_raw_os_error(userns)) }
    );
    let other_user = unsafe {
        let pid = libc::fork();
        if pid == 0 {
            libc::_exit(if libc::setresuid(65532, 65532, 65532) == 0 { 0 } else { errno() });
        }
        let mut st = 0;
        libc::waitpid(pid, &mut st, 0);
        libc::WEXITSTATUS(st)
    };
    println!(
        "| Switch to another uid (65532) | {} |",
        if other_user == 0 { "allowed".into() } else { format!("refused: {}", std::io::Error::from_raw_os_error(other_user)) }
    );
    let bwrap = Command::new("/usr/bin/bwrap")
        .args(["--unshare-all", "--die-with-parent", "--ro-bind", "/", "/", "/bin/true"])
        .output();
    let bwrap = match bwrap {
        Ok(o) if o.status.success() => "starts".to_string(),
        Ok(o) => format!("fails: {}", String::from_utf8_lossy(&o.stderr).trim()),
        Err(e) => format!("not runnable: {e}"),
    };
    println!("| bubblewrap `--unshare-all` (today's worker) | {bwrap} |");
}

fn main() {
    println!("# Worker isolation probe (issue #18, prototype)\n");
    host_facts();

    let dumpable = sibling(true);
    let undumpable = sibling(false);
    let mechanisms: [(&str, &[Confine]); 4] = [
        ("None (baseline)", &[]),
        ("seccomp", &[seccomp]),
        ("Landlock", &[landlock]),
        ("seccomp + Landlock", &[seccomp, landlock]),
    ];
    for (name, confine) in mechanisms {
        println!("\n## {name}\n");
        match run(confine, dumpable, undumpable) {
            Err(e) => println!("Harness error: {e}"),
            Ok((how, rows)) => {
                if !how.is_empty() {
                    println!("Confinement: {how}\n");
                }
                if rows.is_empty() {
                    println!("No checks ran.");
                    continue;
                }
                println!("| Worker tries to | Result | Verdict |\n|---|---|---|");
                for (check, through, denied, must_work) in rows {
                    let (result, verdict) = match (&through, must_work) {
                        (Some(d), true) => (d.clone(), "ok"),
                        (None, true) => (format!("denied ({denied})"), "**BROKEN**"),
                        (Some(d), false) => (d.clone(), "**gap**"),
                        (None, false) => (format!("denied ({denied})"), "blocked"),
                    };
                    println!("| {check} | {result} | {verdict} |");
                }
            }
        }
    }
    unsafe {
        libc::kill(dumpable, libc::SIGKILL);
        libc::kill(undumpable, libc::SIGKILL);
    }
}
