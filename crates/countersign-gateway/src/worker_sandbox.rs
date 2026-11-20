//! The worker sandbox's base layers (ADR 0001): what every grant worker
//! applies to itself, under the namespace sandbox and the filter sandbox alike.

use nix::libc;
use std::{fmt, io};

/// What Landlock gave the grant worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Landlock {
    /// Every access right of this ABI is handled, and none is granted.
    Abi(u8),
    /// The kernel has no Landlock, or it is disabled. The other layers hold.
    Unavailable,
}

/// The base layers a confined grant worker runs under. Non-dumpable memory and
/// the seccomp allow-list are always among them; Landlock depends on the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layers {
    pub landlock: Landlock,
}

impl fmt::Display for Layers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("non-dumpable, ")?;
        match self.landlock {
            Landlock::Abi(abi) => write!(f, "Landlock ABI v{abi}")?,
            Landlock::Unavailable => f.write_str("Landlock unavailable")?,
        }
        f.write_str(", seccomp allow-list")
    }
}

/// A base layer, as [`ConfineError`] names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    NonDumpable,
    Landlock,
    AllowList,
}

impl fmt::Display for Layer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Layer::NonDumpable => "non-dumpable",
            Layer::Landlock => "Landlock",
            Layer::AllowList => "seccomp allow-list",
        })
    }
}

/// The layer that could not be applied, and why. The layers before it stay
/// applied, so the caller can only exit.
#[derive(Debug, thiserror::Error)]
#[error("{layer}: {source}")]
pub struct ConfineError {
    pub layer: Layer,
    #[source]
    pub source: io::Error,
}

/// Confine the calling process as a grant worker.
///
/// Call it while the process has one thread and before it reads any input.
/// Afterwards the process can use the descriptors it holds and those it
/// receives over them, run threads, and signal itself. Any other system call
/// kills it with `SIGSYS`.
pub fn confine() -> Result<Layers, ConfineError> {
    let at = |layer| move |source| ConfineError { layer, source };
    prctl(libc::PR_SET_DUMPABLE, 0).map_err(at(Layer::NonDumpable))?;
    // The allow-list's no_new_privs, set ahead of Landlock and not after it:
    // an unprivileged landlock_restrict_self fails with EPERM without it
    // (landlock_restrict_self(2)).
    prctl(libc::PR_SET_NO_NEW_PRIVS, 1)
        .map_err(|error| io::Error::new(error.kind(), format!("no_new_privs: {error}")))
        .map_err(at(Layer::AllowList))?;
    let landlock = landlock().map_err(at(Layer::Landlock))?;
    allow_list().map_err(at(Layer::AllowList))?;
    Ok(Layers { landlock })
}

fn check(result: libc::c_long) -> io::Result<libc::c_long> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

fn prctl(option: libc::c_int, value: libc::c_ulong) -> io::Result<()> {
    // SAFETY: both options take one integer and no pointers.
    check(unsafe { libc::prctl(option, value, 0, 0, 0) }.into()).map(drop)
}

/// The newest Landlock ABI whose access rights are listed below. A newer
/// kernel is confined as this ABI, and reported as it.
const LANDLOCK_ABI: u8 = 7;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

/// A rule set that handles every access right the kernel's ABI knows and
/// grants none: no file access, no TCP bind or connect from ABI 4, and no
/// signal or abstract-socket reach outside the grant worker from ABI 6.
fn landlock() -> io::Result<Landlock> {
    const VERSION: u32 = 1;
    // SAFETY: a null attribute with size 0 is the documented version query.
    let abi = match check(unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            VERSION,
        )
    }) {
        Ok(abi) => abi.min(LANDLOCK_ABI.into()) as u8,
        // Not built into the kernel, disabled at boot (landlock(7)), or denied
        // by a container profile older than Landlock, which answers EPERM.
        // Only this query may be refused: once the kernel has named an ABI, a
        // failure to apply it is an error.
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::ENOSYS | libc::EOPNOTSUPP | libc::EPERM)
            ) =>
        {
            return Ok(Landlock::Unavailable);
        }
        Err(error) => return Err(error),
    };
    let attr = RulesetAttr {
        // ABI 1 has 13 file rights. REFER (2), TRUNCATE (3) and IOCTL_DEV (5)
        // each added one bit.
        handled_access_fs: match abi {
            1 => 0x1fff,
            2 => 0x3fff,
            3 | 4 => 0x7fff,
            _ => 0xffff,
        },
        handled_access_net: if abi >= 4 { 0b11 } else { 0 },
        scoped: if abi >= 6 { 0b11 } else { 0 },
    };
    // An older kernel rejects a structure longer than the one it knows.
    let size: usize = match abi {
        ..4 => 8,
        4 | 5 => 16,
        _ => 24,
    };
    // SAFETY: `attr` outlives the call and `size` is within it.
    let ruleset =
        check(unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, &attr, size, 0u32) })?
            as libc::c_int;
    // SAFETY: `ruleset` is the descriptor just created, closed exactly once.
    let restricted =
        check(unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset, 0u32) });
    unsafe { libc::close(ruleset) };
    restricted?;
    Ok(Landlock::Abi(abi))
}

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC000_00B7;

/// What a confined grant worker needs, and nothing else.
const ALLOWED: &[libc::c_long] = &[
    // Receiving its streams, then reading and writing them.
    libc::SYS_recvmsg,
    libc::SYS_recvfrom,
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_writev,
    libc::SYS_close,
    libc::SYS_shutdown,
    libc::SYS_setsockopt,
    libc::SYS_epoll_create1,
    libc::SYS_epoll_ctl,
    libc::SYS_epoll_pwait,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_epoll_wait,
    libc::SYS_eventfd2,
    // Threads' synchronisation. Starting one is `clone`, below.
    libc::SYS_set_robust_list,
    libc::SYS_rseq,
    libc::SYS_futex,
    libc::SYS_sigaltstack,
    libc::SYS_rt_sigprocmask,
    // The C library installs its thread-cancellation handler with the first thread.
    libc::SYS_rt_sigaction,
    // Returning from a signal handler. Without it a crash that a handler
    // sees first would end as a filter kill, and be logged as one.
    libc::SYS_rt_sigreturn,
    libc::SYS_sched_yield,
    // A new thread asks the C library for its own attributes, CPU set included.
    libc::SYS_sched_getaffinity,
    libc::SYS_restart_syscall,
    // Memory.
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_mprotect,
    libc::SYS_mremap,
    libc::SYS_madvise,
    libc::SYS_brk,
    // Randomness and clocks.
    libc::SYS_getrandom,
    libc::SYS_clock_gettime,
    // Exit. `abort` looks up the process and thread to signal first.
    libc::SYS_exit,
    libc::SYS_exit_group,
    libc::SYS_getpid,
    libc::SYS_gettid,
];

/// Offsets into `struct seccomp_data`, on a little-endian machine.
const DATA_NR: u32 = 0;
const DATA_ARCH: u32 = 4;
const DATA_ARG0: u32 = 16;
const DATA_ARG1: u32 = 24;
const DATA_ARG4: u32 = 48;

/// What one word of a system call's arguments has to be.
enum Test<'a> {
    /// One of these values.
    OneOf(&'a [u32]),
    /// Any value with this bit set.
    Bit(u32),
}

/// The seccomp filter. A system call outside it kills the whole process.
fn allow_list() -> io::Result<()> {
    const LOAD: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    const EQUAL: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    const BIT_SET: u16 = (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16;
    const RETURN: u16 = (libc::BPF_RET | libc::BPF_K) as u16;
    let op = |code, k, jt, jf| libc::sock_filter { code, jt, jf, k };
    let allow = op(RETURN, libc::SECCOMP_RET_ALLOW, 0, 0);
    let kill = op(RETURN, libc::SECCOMP_RET_KILL_PROCESS, 0, 0);
    let number = |nr: libc::c_long| nr as u32;

    let mut filter = vec![
        // A foreign architecture numbers its system calls differently.
        op(LOAD, DATA_ARCH, 0, 0),
        op(EQUAL, AUDIT_ARCH, 1, 0),
        kill,
        op(LOAD, DATA_NR, 0, 0),
    ];
    // x32 shares x86-64's architecture value and sets this bit in the number.
    #[cfg(target_arch = "x86_64")]
    filter.extend([
        op(
            (libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K) as u16,
            0x4000_0000,
            0,
            1,
        ),
        kill,
    ]);
    // clone3 takes its flags in a structure, which a filter cannot read, so
    // it cannot be allowed for threads alone. It is answered as a kernel
    // without it answers, and the C library then starts the thread with clone.
    // The one call outside the allow-list that does not kill (ADR 0002).
    filter.extend([
        op(EQUAL, number(libc::SYS_clone3), 0, 1),
        op(RETURN, libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32, 0, 0),
    ]);
    for nr in ALLOWED {
        filter.extend([op(EQUAL, number(*nr), 0, 1), allow]);
    }
    // These are allowed only when every listed word of their arguments passes
    // its test. The kernel reads each argument tested below as a 32-bit
    // integer, bar the pointer, so the low word is the whole argument.
    let own_pid = [std::process::id()];
    let conditional: [(libc::c_long, &[(u32, Test)]); 7] = [
        // A grant worker may signal only itself (ADR 0001, decision 6).
        (libc::SYS_kill, &[(DATA_ARG0, Test::OneOf(&own_pid))]),
        (libc::SYS_tgkill, &[(DATA_ARG0, Test::OneOf(&own_pid))]),
        // Duplicating a stream's descriptor and reading its flags. Not
        // F_SETOWN, which has the kernel signal a process of the caller's choice.
        (
            libc::SYS_fcntl,
            &[(
                DATA_ARG1,
                Test::OneOf(&[
                    libc::F_DUPFD_CLOEXEC as u32,
                    libc::F_GETFD as u32,
                    libc::F_GETFL as u32,
                ]),
            )],
        ),
        // A thread. Unlike clone3's, clone's flags are an argument the filter
        // can read.
        (
            libc::SYS_clone,
            &[(DATA_ARG0, Test::Bit(libc::CLONE_THREAD as u32))],
        ),
        // The async runtime wakes itself over a local socket pair, which
        // reaches nothing outside the grant worker.
        (
            libc::SYS_socketpair,
            &[(DATA_ARG0, Test::OneOf(&[libc::AF_UNIX as u32]))],
        ),
        // Switching a received stream between blocking and non-blocking.
        (
            libc::SYS_ioctl,
            &[(DATA_ARG1, Test::OneOf(&[libc::FIONBIO as u32]))],
        ),
        // Writing a stream. A null destination, both words of the pointer:
        // with one, a datagram socket could reach a socket it was not given.
        (
            libc::SYS_sendto,
            &[
                (DATA_ARG4, Test::OneOf(&[0])),
                (DATA_ARG4 + 4, Test::OneOf(&[0])),
            ],
        ),
    ];
    for (nr, tests) in conditional {
        let mut block = Vec::new();
        for (word, test) in tests {
            block.push(op(LOAD, *word, 0, 0));
            match test {
                Test::OneOf(values) => {
                    // A match jumps past the values left to try and the kill.
                    for (tried, value) in values.iter().enumerate() {
                        block.push(op(EQUAL, *value, (values.len() - tried) as u8, 0));
                    }
                }
                Test::Bit(bit) => block.push(op(BIT_SET, *bit, 1, 0)),
            }
            block.push(kill);
        }
        block.push(allow);
        // Another system call skips the block. Inside it every path ends in
        // the kill or the allow, so nothing falls through to the next one.
        filter.push(op(EQUAL, number(nr), 0, block.len() as u8));
        filter.extend(block);
    }
    filter.push(kill);

    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    // SAFETY: `program` points at `filter`, which outlives the call. The
    // kernel copies the filter.
    check(
        unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &program as *const libc::sock_fprog,
            )
        }
        .into(),
    )
    .map(drop)
}
