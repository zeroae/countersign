---
status: accepted
date: 2026-11-19
supersedes: 0001, decision 5, for the `clone3` system call only
---

# `clone3` fails as unsupported in the worker sandbox

A grant worker serves its connections on threads, and must not be able to start a second process. A second process inherits every base layer, but under the filter sandbox it has no process namespace around it: it would outlive the supervisor's kill of the grant worker and keep the stream descriptors it inherited.

The seccomp allow-list can tell a thread from a process under `clone`, whose flags are an argument: it allows `clone` only with `CLONE_THREAD`. It cannot under `clone3`, which takes its flags in a structure, and a seccomp filter reads arguments but not the memory they point to. The first allow-list (#22) allowed `clone3` outright, because the C library starts threads with it. So a compromised grant worker could start a process wherever the kernel has `clone3` (#28).

[ADR 0001](0001-filter-sandbox-for-hosts-without-namespaces.md), decision 5, leaves two answers, and neither works: allow `clone3`, and with it a new process; or leave it off the allow-list, which kills the grant worker when it starts its first thread.

## Decision

1. **The allow-list answers `clone3` with `ENOSYS`**, as a kernel older than `clone3` does. The C library takes that answer as its cue to start the thread with `clone`, which the allow-list checks for `CLONE_THREAD`.
2. **This is the one system call outside the allow-list that does not kill the grant worker.** For every other call, ADR 0001's decision 5 stands. Another exception needs its own ADR.
3. **Both worker sandboxes get it**, because it is part of the base layers.

## Evidence

- The containment test makes a raw `clone3` call without `CLONE_THREAD` from each of two concurrent stand-in grant workers. Before this decision the call started a process. Now it fails with `ENOSYS`, and the stand-in goes on serving its stream on a thread it started after confinement. Measured on glibc 2.39, arm64, kernel 6.17, on 2026-11-19; CI repeats it on x86-64 and arm64.
- Docker's default seccomp profile has answered `clone3` with `ENOSYS` since 20.10.10, for the same reason: its filter cannot read the flags either. So every C library that runs in a container already handles this answer, and a grant worker under Docker's default profile already ran this way before this decision.

## Considered options

- **Keep allowing `clone3`** and record why a second process is acceptable. Rejected: under the filter sandbox the second process escapes the supervisor's kill, which is how a grant is cut off, and holds the grant's streams. The base layers it inherits bound what it can do, not how long it lives.
- **Kill on `clone3`**, as decision 5 says. Rejected: the C library tries `clone3` first for every thread, so the grant worker would die serving its first connection.
- **Allow `clone3` and catch the new process elsewhere**, for example by killing the grant worker's process group, or with a PID limit. Rejected: the filter sandbox exists for hosts that offer an unprivileged supervisor no such control, and each of these is a second mechanism to keep correct where the filter needs one line.

## Consequences

- A compromised grant worker that tries `clone3` is not killed, and its grant is not fenced for it. It learns only that the call is unsupported, and its next forbidden call kills it.
- Code that calls `clone3` directly, without the C library's fallback, fails with `ENOSYS` in a grant worker instead of being killed. Nothing in the grant worker does today, and the runtime test would show it as a failed connection.
- A C library that stopped falling back to `clone` would leave the grant worker unable to start threads. The containment test and the runtime test, on both architectures, would fail first.
