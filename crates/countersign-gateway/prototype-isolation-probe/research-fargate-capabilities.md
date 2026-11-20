# Can bubblewrap create namespaces on Fargate? (issue #18, research)

**Answer.** No. An ECS task on Fargate (Linux) can't get CAP_SYS_ADMIN, privileged mode, a custom or unconfined seccomp profile, or a sysctl that turns on user namespaces. The only capability a Fargate task definition can add is `SYS_PTRACE`. `privileged` and `dockerSecurityOptions` aren't valid on Fargate, and `systemControls` accepts only IPC and `net.*` sysctls. Linux platform version 1.4.0 is still `LATEST`. AWS hasn't announced a newer Linux version, and none of the What's New posts tagged "AWS Fargate" (read 2026-11-19) mention one. On 2025-12-23 AWS closed the "Allow privileged mode on Fargate" request and said: "Given Fargate's security model, we currently do not have plans to introduce elevated privileges." It points those workloads to ECS Managed Instances. Since 1.4.0, Fargate runs containers with containerd. containerd's default seccomp profile (and Docker's) allows `unshare`, `setns`, `mount` and `clone3` only when the container has CAP_SYS_ADMIN. Without it, the profile allows `clone` only if none of the `CLONE_NEW*` flags is set. The probe's numbers match that profile exactly: CapBnd `a80425fb` is the default capability set without SYS_ADMIN, the container runtime installed one seccomp filter, `max_user_namespaces` is 16384, and the call returns EPERM. So your explanation is right: the kernel allows user namespaces and the runtime's seccomp filter refuses them. One part is unconfirmed: AWS doesn't publish which seccomp profile Fargate applies. The open request for this exact capability is aws/containers-roadmap#2102, and AWS hasn't replied to it. The documented way to get CAP_SYS_ADMIN on fully managed compute is ECS Managed Instances, or ECS on EC2 with `privileged` or `capabilities.add: ["SYS_ADMIN"]`.

All sources read on 2026-11-19 unless a different date is given.

## 1. Which capabilities a Fargate task definition can add

Only `SYS_PTRACE`.

- *Amazon ECS task definition parameters for Fargate*, `linuxParameters` → `capabilities` → `add`: "Type: String array / **Valid values: "SYS_PTRACE"**". The same page's `drop` list contains every capability, `SYS_ADMIN` included, so you can drop capabilities but not add them. <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html>
- *KernelCapabilities* (API reference): "Note Tasks launched on AWS Fargate only support adding the SYS_PTRACE kernel capability." <https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_KernelCapabilities.html>
- *LinuxParameters* (API reference): "For tasks that use the Fargate launch type, capabilities is supported for all platform versions but the `add` parameter is only supported if using platform version 1.4.0 or later." <https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_LinuxParameters.html>
- *Fargate security considerations*: "Limited access to Linux capabilities - The environment in which containers run on Fargate is locked down. Additional Linux capabilities, such as CAP_SYS_ADMIN and CAP_NET_ADMIN, are restricted to prevent a privilege escalation. Fargate supports adding the CAP_SYS_PTRACE Linux capability to tasks to allow observability and security tools deployed within the task to monitor the containerized application." <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/fargate-security-considerations.html>

Adding SYS_PTRACE doesn't help here: the seccomp profile turns the namespace syscalls on only for CAP_SYS_ADMIN (section 4).

## 2. privileged, dockerSecurityOptions, systemControls, initProcessEnabled

| Parameter | On Fargate | Source and quote |
|---|---|---|
| `privileged` | Not supported | *ContainerDefinition*: "Note This parameter is not supported for Windows containers or tasks run on AWS Fargate." *Fargate security considerations*: "No privileged containers or access - Features such as privileged containers or access are currently unavailable on Fargate. This will affect uses cases such as running Docker in Docker." The Fargate task-definition parameter page doesn't list `privileged` at all. |
| `dockerSecurityOptions` (seccomp, AppArmor, SELinux labels) | Not valid | *ContainerDefinition*: "This field isn't valid for containers in tasks using the Fargate launch type." Even on EC2 the valid values are only `"no-new-privileges" \| "apparmor:PROFILE" \| "label:value" \| "credentialspec:CredentialSpecFilePath"`. No seccomp option exists in the ECS API on any launch type. |
| `systemControls` (sysctls) | IPC and `net.*` only | *Task definition parameters for Fargate*: "Valid IPC namespace values: "kernel.msgmax" \| "kernel.msgmnb" \| "kernel.msgmni" \| "kernel.sem" \| "kernel.shmall" \| "kernel.shmmax" \| "kernel.shmmni" \| "kernel.shm_rmid_forced", and Sysctls that start with "fs.mqueue.*" / Valid network namespace values: Sysctls that start with "net.*". On Fargate, only namespaced Sysctls that exist within the container are accepted." `user.max_user_namespaces` isn't on the list. It wouldn't help anyway, because it is already 16384. The What's New post of 2023-08-09 gives the same list. |
| `pidMode` | `task` only | "On Linux containers, the only valid value is `task`." This shares one PID namespace across a task's containers. It doesn't let a container create new namespaces. |
| `initProcessEnabled` | Supported, no effect here | *LinuxParameters*: "Run an init process inside the container that forwards signals and reaps processes. This parameter maps to the --init option to docker run." It changes no capability or seccomp setting. |
| `devices`, `maxSwap`, `sharedMemorySize`, `swappiness` | Not supported | *LinuxParameters* notes, e.g. "If you're using tasks that use the Fargate launch type, the devices parameter isn't supported." |

Sources: <https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_ContainerDefinition.html>, <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html>, <https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_LinuxParameters.html>, <https://aws.amazon.com/about-aws/whats-new/2023/08/aws-fargate-pid-namespace-sharing-kernel-configuration/>.

## 3. Fargate Linux platform versions

- *Fargate platform versions for Amazon ECS*: "The `LATEST` Linux platform version is `1.4.0`." Revisions of a platform version bring kernel and OS patches: "New revisions of platform versions are released as the runtime environment evolves, for example, if there are kernel or operating system updates, new features, bug fixes, or security updates." <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/platform-fargate.html>
- *Fargate Linux platform version change log* lists only `1.4.0`. That entry includes: "Added support for the SYS_PTRACE Linux parameter in container definitions", "The container runtime is now using Containerd instead of Docker", and "Based on Amazon Linux 2". Later additions to 1.4.0 (Nov 2020, Jul 2020, May 2020) cover secrets, environment files, IPv6, task metadata v4, UDP NLB and storage encryption. None of them touches capabilities or seccomp. <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/platform-versions-changelog.html>
- Older versions (1.0.0 to 1.3.0) are covered by the deprecation page. <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/platform-versions-retired.html>
- What's New history (fetched from the What's New feed, filtered to the "AWS Fargate" tag, 132 posts): platform version 1.1 (2018-03-26), 1.3 (2018-12-17), 1.4 launch (2020-04-08), "AWS Fargate updates platform version 1.4.0 to be the LATEST version" (2021-03-19). No later post announces a new Linux platform version, and none mentions seccomp or extra capabilities. The newest Fargate-specific posts are about task-retirement windows (2025-12-18) and SOCI v2 (2025-07-03).
- **Unconfirmed:** an announced or roadmap Linux platform version after 1.4.0. I found none in the docs, What's New or containers-roadmap.
- Side note: the change log still says 1.4.0 is "Based on Amazon Linux 2", but the probe saw kernel 6.1.190. That fits the docs' statement that revisions roll out kernel updates without a new version number. AWS doesn't document which host OS the current revision runs.

## 4. Which seccomp profile Fargate applies, and why CLONE_NEWUSER fails

**What the kernel allows.** clone(2), Linux man-pages: "Before Linux 3.8, use of CLONE_NEWUSER required that the caller have three capabilities: CAP_SYS_ADMIN, CAP_SETUID, and CAP_SETGID. Starting with Linux 3.8, no privileges are needed to create a user namespace." <https://man7.org/linux/man-pages/man2/clone.2.html>. Kernel sysctl docs: "max_user_namespaces: The maximum number of user namespaces that any user in the current user namespace may create." <https://docs.kernel.org/admin-guide/sysctl/user.html>. The probe read 16384, so the kernel isn't the obstacle.

**What the runtime's filter does.** seccomp(2): "SECCOMP_RET_ERRNO: This value results in the SECCOMP_RET_DATA portion of the filter's return value being passed to user space as the errno value without executing the system call." <https://man7.org/linux/man-pages/man2/seccomp.2.html>

containerd's default profile, `contrib/seccomp/seccomp_default.go` at commit `03d46bb39732a1fe6e0a1b9b30e55db70fa711ed`:
- The default action is deny (`DefaultAction: specs.ActErrno`, line 600). Each rule that turns on extra syscalls depends on a capability, and the code reads that capability from the container's **bounding** set: `for _, c := range sp.Process.Capabilities.Bounding {` (line 684).
- `case "CAP_SYS_ADMIN":` allows `bpf, clone, clone3, fanotify_init, fsconfig, fsmount, fsopen, fspick, lookup_dcookie, mount, mount_setattr, move_mount, open_tree, perf_event_open, quotactl, quotactl_fd, setdomainname, sethostname, setns, syslog, umount, umount2, unshare` (lines 692–720). No other rule allows `unshare`, so without SYS_ADMIN it hits the default action and returns EPERM.
- `if !admin {`: `clone` is allowed only when `Value: unix.CLONE_NEWNS | unix.CLONE_NEWUTS | unix.CLONE_NEWIPC | unix.CLONE_NEWUSER | unix.CLONE_NEWPID | unix.CLONE_NEWNET | unix.CLONE_NEWCGROUP, ValueTwo: 0, Op: specs.OpMaskedEqual`, meaning none of those flags is set (lines 815–853). The comment there reads: "clone3 is explicitly requested to give ENOSYS instead of the default EPERM, when CAP_SYS_ADMIN is unset" (lines 855–863).
- <https://github.com/containerd/containerd/blob/03d46bb39732a1fe6e0a1b9b30e55db70fa711ed/contrib/seccomp/seccomp_default.go#L684-L865>

Docker's default profile, `moby/profiles` `seccomp/default.json` at commit `9ee3204f0d0cfa19ca2c6a7b0fcf5a2b353954ae` (the file has moved out of `moby/moby`), uses the same rules: `"defaultAction": "SCMP_ACT_ERRNO", "defaultErrnoRet": 1`. One rule allows `clone, clone3, mount, setns, unshare, …` with `"includes": {"caps": ["CAP_SYS_ADMIN"]}`. Another allows `clone` with `"value": 2114060288, "op": "SCMP_CMP_MASKED_EQ"` (0x7E020000 = all `CLONE_NEW*` flags) and `"excludes": {"caps": ["CAP_SYS_ADMIN"]}`. A third makes `clone3` return errno 38 (ENOSYS) without SYS_ADMIN. <https://github.com/moby/profiles/blob/9ee3204f0d0cfa19ca2c6a7b0fcf5a2b353954ae/seccomp/default.json>

**What AWS says Fargate uses.** The change log confirms the runtime: "The container runtime is now using Containerd instead of Docker." AWS doesn't say which seccomp profile Fargate installs. **Unconfirmed:** that it is containerd's default profile unchanged. The probe is consistent with it on every point:
- CapBnd `00000000a80425fb` is exactly the 14 default container capabilities (CHOWN, DAC_OVERRIDE, FOWNER, FSETID, KILL, SETGID, SETUID, SETPCAP, NET_BIND_SERVICE, NET_RAW, SYS_CHROOT, MKNOD, AUDIT_WRITE, SETFCAP). SYS_ADMIN (bit 21) is absent, so the profile drops its SYS_ADMIN block.
- `Seccomp: 2` with one filter means the runtime installed a single filter.
- `unshare(CLONE_NEWUSER)` returns EPERM: `unshare` matches no allow rule.
- bwrap's `clone(CLONE_NEWUSER|…)` returns EPERM, which bwrap reports as "No permissions to create new namespace".

A setuid-root bwrap wouldn't help either. Without SYS_ADMIN in the bounding set, the profile is generated with the same rules, and a setuid exec can't raise capabilities above the bounding set. (This is my inference from the code above and capabilities(7). I didn't test it.)

## 5. aws/containers-roadmap requests

Issue state as of 2026-11-19. On these threads AWS staff show `author_association: NONE`. I'm treating them as staff because they speak for AWS ("We have delivered…") and close issues.

| # | Title | State | AWS response |
|---|---|---|---|
| [2102](https://github.com/aws/containers-roadmap/issues/2102) | [ecs/lambda/fargate] [request]: Allow unprivileged containers to create new user namespaces with clone(2) and unshare(2) | Open, labels Fargate, ECS, Proposed (opened 2023-08-03) | None. Names bubblewrap, nsjail and isolate as the use case. Its author notes that privileged ECS-on-EC2 containers work: "with privileged containers it is possible to create new user namespaces with a non-root (non-zero uid) user." **This is our request.** |
| [1782](https://github.com/aws/containers-roadmap/issues/1782) | [service] [request]: Custom seccomp profile for ECS containers | Open, ECS, Proposed (2022-07-04) | None. |
| [1957](https://github.com/aws/containers-roadmap/issues/1957) | [ECS] [request]: Allow custom seccomp profile or label=disable flag for rootless Podman in Fargate | Open, Fargate, ECS, Proposed (2023-02-09) | None. |
| [2923](https://github.com/aws/containers-roadmap/issues/2923) | [Fargate] [request]: Opt-in io_uring support for ECS tasks on Fargate | Open (2026-11-17) | None. Another case of the same seccomp filter blocking syscalls. |
| [1648](https://github.com/aws/containers-roadmap/issues/1648) | [Fargate] [enhancement request]: elevated privileges for executing reliability tests | Open, Fargate, Proposed (2022-02-10) | None. |
| [1000](https://github.com/aws/containers-roadmap/issues/1000) | [Fargate] [request]: Allow privileged mode | **Closed as completed 2025-12-23** (had been Work in Progress since 2024-10-23) | AbhishekNautiyal, 2025-12-23: "We have delivered support for privileged containers and elevated privileges on fully-managed compute with the ECS Managed Instances launch (#2452)… We are aware that this feature request was originally opened for Fargate… **Given Fargate's security model, we currently do not have plans to introduce elevated privileges.** … Please open a new issue if you require privileged mode support on Fargate." |
| [1027](https://github.com/aws/containers-roadmap/issues/1027) | [Fargate] [request]: Provide the ability to use ebpf on fargate instances. | Closed as completed 2025-12-23 | Same reply as #1000: delivered on ECS Managed Instances, no plan for Fargate. |
| [1356](https://github.com/aws/containers-roadmap/issues/1356) | [ECS, Fargate]: Support for running Docker-in-Docker containers | Closed as completed 2026-01-09 | AbhishekNautiyal: Docker-in-Docker runs on ECS Managed Instances. Closed "so that we…" track compute options separately. |
| [774](https://github.com/aws/containers-roadmap/issues/774) | Add support for userns in ecs-agent and TaskDefinition | Open (2022) | None. This one is about userns-remap for the container itself, not namespaces created inside it. |

## 6. Documented alternatives

- **ECS Managed Instances.** *Managed Instances security*: "Supported capabilities - You can opt-in to all privileged Linux capabilities, including CAP_NET_ADMIN, CAP_SYS_ADMIN, CAP_BPF, and CAP_PERFMON." and "Explicit configuration required - You must explicitly configure your Amazon ECS Managed Instances capacity provider to enable privileged Linux capabilities." Its task-definition parameter page lists `privileged`, but says of `dockerSecurityOptions`: "This parameter isn't supported for tasks running on Amazon ECS Managed Instances." So you get SYS_ADMIN or privileged there, but no custom seccomp profile. With SYS_ADMIN in the bounding set, the default profile allows `unshare` and `clone(CLONE_NEW*)` (section 4). The overview page describes the hosts as having "kernel-level mandatory access controls via SELinux". **Unconfirmed:** whether that SELinux policy allows bwrap's mounts. <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/managed-instances-security.html>, <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ManagedInstances.html>, <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters-managed-instances.html>
- **ECS on EC2.** `privileged` is documented ("When this parameter is true, the container is given elevated privileges on the host container instance (similar to the root user)"). `KernelCapabilities.add` accepts the full list, `SYS_ADMIN` included, with only Fargate restricted. Custom seccomp still isn't in the task definition. #1782 reports that the only option there is a daemon-wide Docker `seccomp-profile`. <https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_ContainerDefinition.html>, <https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_KernelCapabilities.html>
- **EKS on Fargate** is no better: "Privileged containers aren't supported on Fargate." and "Pods running on Fargate can't specify HostPort or HostNetwork in the Pod manifest." (#1102 still asks for SYS_PTRACE on EKS Fargate.) <https://docs.aws.amazon.com/eks/latest/userguide/fargate.html>

## Sources

All read 2026-11-19.

- AWS, *Amazon ECS task definition parameters for Fargate* — <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html>
- AWS, *KernelCapabilities* (API) — <https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_KernelCapabilities.html>
- AWS, *LinuxParameters* (API) — <https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_LinuxParameters.html>
- AWS, *ContainerDefinition* (API) — <https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_ContainerDefinition.html>
- AWS, *Fargate security considerations for Amazon ECS* — <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/fargate-security-considerations.html>
- AWS, *Fargate platform versions for Amazon ECS* — <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/platform-fargate.html>
- AWS, *Fargate Linux platform version change log* — <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/platform-versions-changelog.html>
- AWS, *Fargate Linux platform version deprecation* — <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/platform-versions-retired.html>
- AWS What's New: platform version 1.4 launch (2020-04-08) <https://aws.amazon.com/about-aws/whats-new/2020/04/aws-fargate-launches-platform-version-14/>; 1.4.0 becomes LATEST (2021-03-19) <https://aws.amazon.com/about-aws/whats-new/2021/03/aws-fargate-updates-platform-version-1-4-0-to-be-the-latest-version/>; PID sharing and sysctls (2023-08-09) <https://aws.amazon.com/about-aws/whats-new/2023/08/aws-fargate-pid-namespace-sharing-kernel-configuration/>; the feed filtered to the "AWS Fargate" tag, via `https://aws.amazon.com/api/dirs/items/search?item.directoryId=whats-new-v2&tags.id=whats-new-v2%23general-products%23aws-fargate`
- AWS, *Amazon ECS Managed Instances* — <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ManagedInstances.html>; *security* — <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/managed-instances-security.html>; *task definition parameters* — <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters-managed-instances.html>
- AWS, *EKS: AWS Fargate* — <https://docs.aws.amazon.com/eks/latest/userguide/fargate.html>
- containerd, `contrib/seccomp/seccomp_default.go` @ `03d46bb3` — <https://github.com/containerd/containerd/blob/03d46bb39732a1fe6e0a1b9b30e55db70fa711ed/contrib/seccomp/seccomp_default.go>
- moby, `seccomp/default.json` @ `9ee3204f` — <https://github.com/moby/profiles/blob/9ee3204f0d0cfa19ca2c6a7b0fcf5a2b353954ae/seccomp/default.json>
- Linux man-pages, clone(2) — <https://man7.org/linux/man-pages/man2/clone.2.html>; seccomp(2) — <https://man7.org/linux/man-pages/man2/seccomp.2.html>
- Linux kernel docs, `/proc/sys/user` — <https://docs.kernel.org/admin-guide/sysctl/user.html>
- aws/containers-roadmap issues #2102, #1782, #1957, #2923, #1648, #1000, #1027, #1356, #774 — <https://github.com/aws/containers-roadmap/issues>
