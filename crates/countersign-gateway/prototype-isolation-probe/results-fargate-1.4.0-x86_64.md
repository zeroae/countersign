# Worker isolation probe (issue #18, prototype)
## Host
| Fact | Value |
|---|---|
| Kernel | 6.1.190 x86_64 |
| uid / gid | 65531 / 65531 |
| CapEff | 0000000000000000 |
| CapBnd | 00000000a80425fb |
| NoNewPrivs | 0 |
| Seccomp | 2 |
| Seccomp_filters | 1 |
| LSMs | unreadable (No such file or directory (os error 2)) |
| max_user_namespaces | 16384 |
| Yama ptrace_scope | 1 |
| Landlock | ABI v2 |
| Unprivileged user namespace | refused: Operation not permitted (os error 1) |
| Switch to another uid (65532) | refused: Operation not permitted (os error 1) |
| bubblewrap `--unshare-all` (today's worker) | fails: bwrap: No permissions to create new namespace, likely because the kernel does not allow non-privileged user namespaces. See <https://deb.li/bubblewrap> or <file:///usr/share/doc/bubblewrap/README.Debian.gz>. |
## None (baseline)
| Worker tries to | Result | Verdict |
|---|---|---|
| Receive its streams by SCM_RIGHTS | got "stream-ok" | ok |
| Open a file (/etc/hostname) | read 1 bytes | **gap** |
| Read the supervisor's environment | read 486 bytes | **gap** |
| Open a TCP connection | reached kernel: Connection refused (os error 111) | **gap** |
| Send a UDP datagram | datagram sent | **gap** |
| Execute a program | /bin/true ran | **gap** |
| Read supervisor memory | denied (Operation not permitted (os error 1)) | blocked |
| Read another worker's memory (dumpable) | denied (Operation not permitted (os error 1)) | blocked |
| Read another worker's memory (non-dumpable) | denied (Operation not permitted (os error 1)) | blocked |
## seccomp
Confinement: deny-list filter installed
| Worker tries to | Result | Verdict |
|---|---|---|
| Receive its streams by SCM_RIGHTS | got "stream-ok" | ok |
| Open a file (/etc/hostname) | denied (Operation not permitted (os error 1)) | blocked |
| Read the supervisor's environment | denied (Operation not permitted (os error 1)) | blocked |
| Open a TCP connection | denied (Operation not permitted (os error 1)) | blocked |
| Send a UDP datagram | denied (Operation not permitted (os error 1)) | blocked |
| Execute a program | denied (Operation not permitted (os error 1)) | blocked |
| Read supervisor memory | denied (Operation not permitted (os error 1)) | blocked |
| Read another worker's memory (dumpable) | denied (Operation not permitted (os error 1)) | blocked |
| Read another worker's memory (non-dumpable) | denied (Operation not permitted (os error 1)) | blocked |
## Landlock
Confinement: ABI v2
| Worker tries to | Result | Verdict |
|---|---|---|
| Receive its streams by SCM_RIGHTS | got "stream-ok" | ok |
| Open a file (/etc/hostname) | denied (Permission denied (os error 13)) | blocked |
| Read the supervisor's environment | denied (Permission denied (os error 13)) | blocked |
| Open a TCP connection | reached kernel: Connection refused (os error 111) | **gap** |
| Send a UDP datagram | datagram sent | **gap** |
| Execute a program | denied (Permission denied (os error 13)) | blocked |
| Read supervisor memory | denied (Operation not permitted (os error 1)) | blocked |
| Read another worker's memory (dumpable) | denied (Operation not permitted (os error 1)) | blocked |
| Read another worker's memory (non-dumpable) | denied (Operation not permitted (os error 1)) | blocked |
## seccomp + Landlock
Confinement: deny-list filter installed; ABI v2
| Worker tries to | Result | Verdict |
|---|---|---|
| Receive its streams by SCM_RIGHTS | got "stream-ok" | ok |
| Open a file (/etc/hostname) | denied (Operation not permitted (os error 1)) | blocked |
| Read the supervisor's environment | denied (Operation not permitted (os error 1)) | blocked |
| Open a TCP connection | denied (Operation not permitted (os error 1)) | blocked |
| Send a UDP datagram | denied (Operation not permitted (os error 1)) | blocked |
| Execute a program | denied (Operation not permitted (os error 1)) | blocked |
| Read supervisor memory | denied (Operation not permitted (os error 1)) | blocked |
| Read another worker's memory (dumpable) | denied (Operation not permitted (os error 1)) | blocked |
| Read another worker's memory (non-dumpable) | denied (Operation not permitted (os error 1)) | blocked |
