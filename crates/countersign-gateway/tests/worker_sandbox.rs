//! Two concurrent stand-in grant workers confine themselves through the
//! worker sandbox module, receive a stream as a grant worker does, and then
//! try what a compromised grant worker would try.
//!
//! This test is its own harness (`harness = false`): it starts the stand-ins
//! by running itself again, as the supervisor runs the Gateway executable, so
//! each stand-in confines a fresh process that has one thread.

#[cfg(not(target_os = "linux"))]
fn main() {}

#[cfg(target_os = "linux")]
fn main() {
    linux::main()
}

#[cfg(target_os = "linux")]
mod linux {
    use countersign_gateway::worker_sandbox::confine;
    use nix::{
        libc,
        sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg},
    };
    use std::{
        ffi::CString,
        io::{BufRead, BufReader, IoSlice, IoSliceMut, Write},
        net::{TcpListener, UdpSocket},
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::{
                net::{UnixDatagram, UnixStream},
                process::ExitStatusExt,
            },
        },
        process::{Child, Command, Stdio},
    };

    /// The host a stand-in runs on.
    const UNCONFINED: &str = "unconfined";
    const CONFINED: &str = "confined";
    const NO_LANDLOCK: &str = "no-landlock";
    const LANDLOCK_REFUSED: &str = "landlock-refused";

    /// Stands in for a secret in the supervisor's or a grant worker's memory.
    static SECRET: [u8; 16] = *b"keep-this-secret";

    pub fn main() {
        let args: Vec<String> = std::env::args().skip(1).collect();
        // Yama's default lets a process read only its descendants' memory,
        // which alone would refuse every memory read below. The supervisor and
        // each stand-in opt out, so the worker sandbox is what refuses them.
        // SAFETY: the option takes one integer. Without Yama it fails, unneeded.
        unsafe { libc::prctl(libc::PR_SET_PTRACER, libc::PR_SET_PTRACER_ANY, 0, 0, 0) };
        if let [role, mode] = args.as_slice()
            && role == "stand-in"
        {
            stand_in(mode);
        }
        let mut failed = 0;
        for (name, test) in TESTS {
            match std::panic::catch_unwind(test) {
                Ok(()) => println!("test {name} ... ok"),
                Err(_) => {
                    println!("test {name} ... FAILED");
                    failed += 1;
                }
            }
        }
        println!("{} passed, {failed} failed", TESTS.len() - failed);
        std::process::exit(if failed == 0 { 0 } else { 1 });
    }

    // ---------- the stand-in grant worker ----------

    fn stand_in(host: &str) -> ! {
        let layers = if host == UNCONFINED {
            "unconfined".into()
        } else {
            // A host that lacks or refuses part of the worker sandbox, stood
            // in for by a filter of the test's own that answers for the kernel.
            match host {
                NO_LANDLOCK => answer(libc::SYS_landlock_create_ruleset, libc::ENOSYS),
                LANDLOCK_REFUSED => answer(libc::SYS_landlock_restrict_self, libc::EPERM),
                _ => assert_eq!(host, CONFINED),
            }
            match confine() {
                Ok(layers) => layers.to_string(),
                Err(error) => {
                    eprintln!("{error}");
                    std::process::exit(3);
                }
            }
        };
        // Its stream arrives over the control socket, as a grant worker's do.
        let mut byte = [0u8; 1];
        let mut iov = [IoSliceMut::new(&mut byte)];
        let mut space = nix::cmsg_space!([i32; 1]);
        let message = recvmsg::<()>(0, &mut iov, Some(&mut space), MsgFlags::MSG_CMSG_CLOEXEC)
            .expect("control message");
        let stream = message
            .cmsgs()
            .expect("control data")
            .find_map(|control| match control {
                ControlMessageOwned::ScmRights(fds) => fds.first().copied(),
                _ => None,
            })
            .expect("a stream descriptor");
        // SAFETY: recvmsg allocated this descriptor for this process just now.
        let stream = unsafe { UnixStream::from_raw_fd(stream) };
        // It serves the stream on a thread, as a grant worker serves a connection.
        std::thread::spawn(move || serve(stream, &layers))
            .join()
            .expect("stream thread");
        std::process::exit(0);
    }

    /// Make one system call fail with `errno` from now on, as a kernel without
    /// it, or a host that refuses it, would.
    fn answer(nr: libc::c_long, errno: i32) {
        let op = |code: u32, k: u32, jt, jf| libc::sock_filter {
            code: code as u16,
            jt,
            jf,
            k,
        };
        let mut filter = [
            op(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, 0),
            op(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, nr as u32, 0, 1),
            op(
                libc::BPF_RET | libc::BPF_K,
                libc::SECCOMP_RET_ERRNO | errno as u32,
                0,
                0,
            ),
            op(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ALLOW, 0, 0),
        ];
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_mut_ptr(),
        };
        // SAFETY: `program` points at `filter`, which outlives both calls.
        let installed = unsafe {
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &raw const program,
            )
        };
        assert_eq!(installed, 0, "the test's own filter");
    }

    fn serve(stream: UnixStream, layers: &str) {
        let mut reply = stream.try_clone().expect("stream clone");
        writeln!(
            reply,
            "ready {} {} {layers}",
            std::process::id(),
            SECRET.as_ptr() as usize
        )
        .expect("ready line");
        for line in BufReader::new(stream).lines() {
            let line = line.expect("command");
            let words: Vec<&str> = line.split(' ').collect();
            let number = |i: usize| words[i].parse::<usize>().expect("number");
            let result = match words[0] {
                "ping" => Ok(()),
                "open" => open(words[1]),
                "tcp" => tcp(number(1) as u16),
                "udp" => udp(number(1) as u16),
                "exec" => exec(),
                "read-memory" => read_memory(number(1) as libc::pid_t, number(2)),
                "signal" => signal(number(1) as libc::pid_t, number(2) as libc::c_int),
                "trace-me" => trace_me(),
                #[cfg(target_arch = "x86_64")]
                "x32" => x32(),
                #[cfg(target_arch = "x86_64")]
                "i386" => i386(),
                other => panic!("unknown command {other}"),
            };
            match result {
                Ok(()) => writeln!(reply, "ok"),
                Err(errno) => writeln!(reply, "errno {errno}"),
            }
            .expect("reply line");
        }
    }

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    fn done(result: impl Into<i64>) -> Result<(), i32> {
        if result.into() < 0 {
            Err(errno())
        } else {
            Ok(())
        }
    }

    fn open(path: &str) -> Result<(), i32> {
        let path = CString::new(path).unwrap();
        // SAFETY: `path` is a NUL-terminated string that outlives the call.
        done(unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) })
    }

    fn loopback(port: u16) -> libc::sockaddr_in {
        libc::sockaddr_in {
            sin_family: libc::AF_INET as _,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_be_bytes([127, 0, 0, 1]).to_be(),
            },
            sin_zero: [0; 8],
        }
    }

    fn tcp(port: u16) -> Result<(), i32> {
        let address = loopback(port);
        // SAFETY: `address` outlives the calls and its size is passed with it.
        unsafe {
            let socket = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
            done(socket)?;
            done(libc::connect(
                socket,
                (&raw const address).cast(),
                size_of::<libc::sockaddr_in>() as _,
            ))
        }
    }

    fn udp(port: u16) -> Result<(), i32> {
        let address = loopback(port);
        // SAFETY: the buffer and `address` outlive the calls, with their sizes.
        unsafe {
            let socket = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
            done(socket)?;
            done(libc::sendto(
                socket,
                b"x".as_ptr().cast(),
                1,
                0,
                (&raw const address).cast(),
                size_of::<libc::sockaddr_in>() as _,
            ) as i64)
        }
    }

    /// Replaces the stand-in with `/bin/true` when it gets through, so the
    /// supervisor then sees a clean exit instead of a reply.
    fn exec() -> Result<(), i32> {
        let path = CString::new("/bin/true").unwrap();
        let argv = [path.as_ptr(), std::ptr::null()];
        // SAFETY: `argv` is a NULL-terminated array of NUL-terminated strings.
        done(unsafe { libc::execv(path.as_ptr(), argv.as_ptr()) })
    }

    fn read_memory(pid: libc::pid_t, address: usize) -> Result<(), i32> {
        let mut buffer = [0u8; SECRET.len()];
        let local = libc::iovec {
            iov_base: buffer.as_mut_ptr().cast(),
            iov_len: buffer.len(),
        };
        let remote = libc::iovec {
            iov_base: address as *mut _,
            iov_len: buffer.len(),
        };
        // SAFETY: `local` points at `buffer`; the kernel validates `remote`.
        done(unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) } as i64)
    }

    fn signal(pid: libc::pid_t, signal: libc::c_int) -> Result<(), i32> {
        // SAFETY: kill takes two integers.
        done(unsafe { libc::kill(pid, signal) })
    }

    /// A system call no grant worker needs.
    fn trace_me() -> Result<(), i32> {
        // SAFETY: PTRACE_TRACEME takes no pointers.
        done(unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) })
    }

    /// `getpid` by its x32 number: x86-64's architecture value, another table.
    #[cfg(target_arch = "x86_64")]
    fn x32() -> Result<(), i32> {
        // SAFETY: getpid takes no arguments.
        done(unsafe { libc::syscall(0x4000_0000 | libc::SYS_getpid) })
    }

    /// `getpid` by its i386 number, through the 32-bit entry point.
    #[cfg(target_arch = "x86_64")]
    fn i386() -> Result<(), i32> {
        let result: i32;
        // SAFETY: i386 system call 20 is getpid, which takes no arguments.
        // `int 0x80` leaves every register but eax as it was.
        unsafe { std::arch::asm!("int 0x80", inout("eax") 20 => result) };
        if result < 0 { Err(-result) } else { Ok(()) }
    }

    // ---------- the supervisor's side ----------

    struct StandIn {
        child: Child,
        pid: libc::pid_t,
        secret: usize,
        layers: String,
        commands: UnixStream,
        replies: BufReader<UnixStream>,
    }

    #[derive(Debug, PartialEq)]
    enum Outcome {
        /// The stand-in did it.
        GotThrough,
        /// The kernel answered with this error.
        Errno(i32),
        /// The stand-in died of this signal.
        Killed(i32),
    }

    impl Outcome {
        fn refused(&self) -> bool {
            matches!(
                self,
                Outcome::Killed(libc::SIGSYS) | Outcome::Errno(libc::EPERM | libc::EACCES)
            )
        }
    }

    impl StandIn {
        /// Start a stand-in the way the supervisor starts a grant worker: a
        /// fresh process, a cleared environment, the control socket as its
        /// standard input, and its stream handed over by `SCM_RIGHTS`.
        fn start(host: &str) -> Self {
            let (control, child_control) = UnixDatagram::pair().unwrap();
            let child = Command::new(std::env::current_exe().unwrap())
                .env_clear()
                .args(["stand-in", host])
                .stdin(Stdio::from(OwnedFd::from(child_control)))
                .stdout(Stdio::null())
                .spawn()
                .unwrap();
            let (stream, theirs) = UnixStream::pair().unwrap();
            sendmsg::<()>(
                control.as_raw_fd(),
                &[IoSlice::new(&[1])],
                &[ControlMessage::ScmRights(&[theirs.as_raw_fd()])],
                MsgFlags::MSG_NOSIGNAL,
                None,
            )
            .unwrap();
            drop(theirs);
            let mut replies = BufReader::new(stream.try_clone().unwrap());
            let mut ready = String::new();
            replies.read_line(&mut ready).unwrap();
            let words: Vec<&str> = ready.trim_end().splitn(4, ' ').collect();
            assert_eq!(words[0], "ready", "the stand-in never served its stream");
            StandIn {
                child,
                pid: words[1].parse().unwrap(),
                secret: words[2].parse().unwrap(),
                layers: words[3].to_owned(),
                commands: stream,
                replies,
            }
        }

        fn attempt(&mut self, command: &str) -> Outcome {
            writeln!(self.commands, "{command}").unwrap();
            let mut reply = String::new();
            // A stand-in that died by the filter closes its stream instead.
            let _ = self.replies.read_line(&mut reply);
            match reply.trim_end().split_once(' ') {
                _ if reply.trim_end() == "ok" => Outcome::GotThrough,
                Some(("errno", errno)) => Outcome::Errno(errno.parse().unwrap()),
                _ => {
                    let status = self.child.wait().unwrap();
                    match status.signal() {
                        Some(signal) => Outcome::Killed(signal),
                        // Only a successful exec ends a stand-in cleanly.
                        None => {
                            assert_eq!(status.code(), Some(0), "stand-in failed: {status}");
                            Outcome::GotThrough
                        }
                    }
                }
            }
        }
    }

    impl Drop for StandIn {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    struct KillOnDrop<'a>(&'a mut Child);
    impl Drop for KillOnDrop<'_> {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// What the attempt is aimed at, when it needs a process to aim at.
    struct Target {
        supervisor_pid: u32,
        supervisor_secret: usize,
        other_pid: libc::pid_t,
        other_secret: usize,
    }

    /// Each of two concurrent stand-ins makes the attempt in turn, on a fresh
    /// pair, while the other stand-in is alive to be its target. The other
    /// stand-in must be unharmed afterwards.
    fn each_of_two(
        host: &str,
        command: impl Fn(&Target) -> String,
        expect: impl Fn(&Outcome) -> bool,
        expectation: &str,
    ) {
        for attacker in 0..2 {
            let mut pair = [StandIn::start(host), StandIn::start(host)];
            let other = &pair[1 - attacker];
            let command = command(&Target {
                supervisor_pid: std::process::id(),
                supervisor_secret: SECRET.as_ptr() as usize,
                other_pid: other.pid,
                other_secret: other.secret,
            });
            let outcome = pair[attacker].attempt(&command);
            assert!(
                expect(&outcome),
                "stand-in {attacker}, `{command}`: expected {expectation}, got {outcome:?}"
            );
            assert_eq!(
                pair[1 - attacker].attempt("ping"),
                Outcome::GotThrough,
                "stand-in {attacker}'s `{command}` harmed the other stand-in"
            );
        }
    }

    fn refused(command: impl Fn(&Target) -> String) {
        each_of_two(CONFINED, command, Outcome::refused, "a refusal");
    }

    /// Unconfined, the same attempt gets through: the attempt is real, and it
    /// is the worker sandbox that refuses it.
    fn refused_only_when_confined(command: impl Fn(&Target) -> String) {
        each_of_two(
            UNCONFINED,
            &command,
            |o| *o == Outcome::GotThrough,
            "success",
        );
        refused(command);
    }

    type Test = (&'static str, fn());
    const TESTS: &[Test] = &[
        ("a_confined_grant_worker_reports_its_layers", || {
            let stand_in = StandIn::start(CONFINED);
            let layers: Vec<&str> = stand_in.layers.split(", ").collect();
            let [non_dumpable, landlock, allow_list] = layers[..] else {
                panic!("{layers:?}");
            };
            assert_eq!(non_dumpable, "non-dumpable");
            assert_eq!(allow_list, "seccomp allow-list");
            // The kernel decides which. Either way the stand-in started.
            let abi = landlock.strip_prefix("Landlock ABI v");
            assert!(
                landlock == "Landlock unavailable"
                    || abi.is_some_and(|abi| abi.parse::<u8>().is_ok_and(|abi| abi >= 1)),
                "{landlock}"
            );
        }),
        ("without_landlock_it_says_so_and_is_still_confined", || {
            let stand_in = StandIn::start(NO_LANDLOCK);
            assert_eq!(
                stand_in.layers,
                "non-dumpable, Landlock unavailable, seccomp allow-list"
            );
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            for command in [
                "open /etc/hostname".to_owned(),
                format!("tcp {port}"),
                "exec".into(),
            ] {
                each_of_two(
                    NO_LANDLOCK,
                    |_| command.clone(),
                    Outcome::refused,
                    "a refusal",
                );
            }
        }),
        ("a_layer_the_host_refuses_fails_confinement_by_name", || {
            let output = Command::new(std::env::current_exe().unwrap())
                .env_clear()
                .args(["stand-in", LANDLOCK_REFUSED])
                .stdin(Stdio::null())
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(3), "{output:?}");
            assert_eq!(
                String::from_utf8_lossy(&output.stderr),
                "Landlock: Operation not permitted (os error 1)\n"
            );
        }),
        ("its_stream_arrives_and_its_threads_work", || {
            // `start` returns once the thread serving the stream said `ready`.
            each_of_two(
                CONFINED,
                |_| "ping".into(),
                |o| *o == Outcome::GotThrough,
                "a reply",
            );
        }),
        ("opening_a_file_is_refused", || {
            refused_only_when_confined(|_| "open /etc/hostname".into());
        }),
        ("reading_the_supervisors_environment_is_refused", || {
            refused_only_when_confined(|t| format!("open /proc/{}/environ", t.supervisor_pid));
        }),
        ("reading_the_supervisors_memory_is_refused", || {
            refused_only_when_confined(|t| {
                format!("read-memory {} {}", t.supervisor_pid, t.supervisor_secret)
            });
        }),
        ("reading_the_other_grant_workers_memory_is_refused", || {
            refused_only_when_confined(|t| {
                format!("read-memory {} {}", t.other_pid, t.other_secret)
            });
        }),
        (
            "an_unconfined_process_cannot_read_a_grant_workers_memory",
            || {
                // Non-dumpable memory, on its own: this reader runs under no filter.
                let mut reader = StandIn::start(UNCONFINED);
                let worker = StandIn::start(CONFINED);
                assert_eq!(
                    reader.attempt(&format!("read-memory {} {}", worker.pid, worker.secret)),
                    Outcome::Errno(libc::EPERM)
                );
            },
        ),
        (
            "the_grant_worker_is_confined_before_it_is_sent_anything",
            || {
                // The Gateway's own grant worker, started as the supervisor starts
                // it, less bubblewrap. Nothing has been sent to it yet.
                let (control, child_control) = UnixDatagram::pair().unwrap();
                let mut worker = Command::new(env!("CARGO_BIN_EXE_countersign-gateway"))
                    .env_clear()
                    .arg("grant-worker")
                    .stdin(Stdio::from(OwnedFd::from(child_control)))
                    .stdout(Stdio::null())
                    .spawn()
                    .unwrap();
                let status = format!("/proc/{}/status", worker.id());
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
                let confined = loop {
                    let status = std::fs::read_to_string(&status).unwrap();
                    let field = |name: &str| {
                        let line = status.lines().find(|line| line.starts_with(name));
                        line.and_then(|line| line.split_whitespace().nth(1).map(str::to_owned))
                    };
                    // 2 is filter mode.
                    if field("Seccomp:").as_deref() == Some("2") {
                        break field("NoNewPrivs:").as_deref() == Some("1");
                    }
                    if std::time::Instant::now() > deadline {
                        break false;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                };
                let _guard = KillOnDrop(&mut worker);
                assert!(confined, "the grant worker waited for input unconfined");
                // Asked as the startup probe asks, it reports its Landlock layer and exits.
                control.send(&[0]).unwrap();
                let mut report = [0u8; 2];
                assert_eq!(control.recv(&mut report).unwrap(), 1);
                assert!(_guard.0.wait().unwrap().success());
            },
        ),
        ("a_tcp_connection_is_refused", || {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            refused_only_when_confined(|_| format!("tcp {port}"));
        }),
        ("a_udp_datagram_is_refused", || {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            let port = socket.local_addr().unwrap().port();
            refused_only_when_confined(|_| format!("udp {port}"));
        }),
        ("running_a_program_is_refused", || {
            refused_only_when_confined(|_| "exec".into());
        }),
        ("signalling_another_process_is_refused", || {
            // Signal 0 only asks whether the signal may be sent.
            refused_only_when_confined(|t| format!("signal {} 0", t.other_pid));
            refused(|t| format!("signal {} {}", t.other_pid, libc::SIGKILL));
            refused(|t| format!("signal {} {}", t.supervisor_pid, libc::SIGKILL));
            // Its process group, which holds the supervisor.
            refused(|_| format!("signal 0 {}", libc::SIGKILL));
        }),
        ("signalling_itself_works", || {
            for attacker in 0..2 {
                let mut pair = [StandIn::start(CONFINED), StandIn::start(CONFINED)];
                let pid = pair[attacker].pid;
                assert_eq!(
                    pair[attacker].attempt(&format!("signal {pid} 0")),
                    Outcome::GotThrough
                );
                assert_eq!(
                    pair[attacker].attempt(&format!("signal {pid} {}", libc::SIGTERM)),
                    Outcome::Killed(libc::SIGTERM)
                );
                assert_eq!(pair[1 - attacker].attempt("ping"), Outcome::GotThrough);
            }
        }),
        ("a_forbidden_system_call_kills_it_with_sigsys", || {
            each_of_two(
                CONFINED,
                |_| "trace-me".into(),
                |o| *o == Outcome::Killed(libc::SIGSYS),
                "death by SIGSYS",
            );
        }),
        #[cfg(target_arch = "x86_64")]
        ("a_system_call_in_the_x32_range_kills_it", || {
            each_of_two(
                CONFINED,
                |_| "x32".into(),
                |o| *o == Outcome::Killed(libc::SIGSYS),
                "death by SIGSYS",
            );
        }),
        #[cfg(target_arch = "x86_64")]
        ("a_system_call_from_a_foreign_architecture_kills_it", || {
            each_of_two(
                UNCONFINED,
                |_| "i386".into(),
                |o| *o == Outcome::GotThrough,
                "success",
            );
            each_of_two(
                CONFINED,
                |_| "i386".into(),
                |o| *o == Outcome::Killed(libc::SIGSYS),
                "death by SIGSYS",
            );
        }),
    ];
}
