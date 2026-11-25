# Spec #21: Run grant workers in a filter sandbox on hosts without namespaces

- Status: accepted
- Epic: E1 Run grant workers in a filter sandbox on hosts without namespaces
- Written by: sodre
- Exported: 2026-11-25, by `.claude/plugins/foresight/scripts/export-spec.py 21`

This file is the spec's text as its issue held it when the spec closed. It is never edited.

---

## Problem Statement

An operator cannot run the Countersign Gateway on ECS Fargate, or on any host that refuses unprivileged user namespaces. Every grant worker starts inside bubblewrap, and bubblewrap needs to create user, mount, PID and network namespaces. Fargate's container runtime refuses that to every task, and Fargate offers no way to add CAP_SYS_ADMIN, run privileged or change the seccomp profile. So `countersign-gateway serve` exits at its startup check with `bwrap: No permissions to create new namespace`, and a desktop-approved mTLS integration that passes end to end in Docker Compose cannot be deployed there (#18).

The per-grant isolation contract in the design record allows isolation "by user principal/container or equivalent OS sandbox", but the Gateway knows only one sandbox, and nothing defines what an equivalent one is.

## Solution

The operator chooses a worker sandbox in the Gateway configuration:

- **`"namespaces"`** (the default): the namespace sandbox, today's behaviour plus stronger base layers. It stays the recommendation wherever the host allows it.
- **`"filter"`**: the filter sandbox, for hosts that cannot give a grant worker its own namespaces. The kernel refuses every action a grant worker does not need.

Every grant worker, in either sandbox, gets the same base layers: a seccomp allow-list, Landlock as far as the kernel offers it, non-dumpable memory, and no inherited descriptors or environment. The namespace sandbox adds namespaces on top. The Gateway never falls back from one sandbox to the other. Startup probes the chosen sandbox and fails closed, with an error that names the sandbox and the layer that failed.

ADR 0001 records the decision and the evidence for it: a probe run on real Fargate 1.4.0, on x86-64 and arm64.

## User Stories

1. As an operator on ECS Fargate, I want to set `worker_sandbox` to `"filter"`, so that the Gateway starts on a host that refuses namespaces.
2. As an operator on a host that allows namespaces, I want to leave my configuration unchanged, so that my Gateway keeps the namespace sandbox without my doing anything.
3. As an operator, I want an unknown `worker_sandbox` value to fail configuration loading, so that a typo cannot select a sandbox I did not mean.
4. As an operator, I want the Gateway never to switch sandboxes on its own, so that a kernel or container-profile change cannot quietly weaken isolation.
5. As an operator, I want startup to probe a real grant worker under the sandbox I chose, so that a broken sandbox stops the Gateway before it serves traffic.
6. As an operator, I want the startup error to name the sandbox and the layer that failed, so that I know what the host refused.
7. As an operator, I want the startup error to point me to the operator guide rather than suggest the other sandbox, so that I read the trade-off before choosing the weaker one.
8. As an operator, I want startup to log the sandbox in use and every layer applied, including the Landlock ABI version or that Landlock is unavailable, so that I can see what protects my grant workers.
9. As an operator, I want the filter sandbox to start on a kernel without Landlock, so that older kernels are not locked out.
10. As an operator running shared mode on Fargate, I want the filter sandbox to keep concurrent users' grant workers apart, so that I can serve several users from one Gateway.
11. As an operator running a sidecar on Fargate, I want the filter sandbox to work with a single Workload, so that both deployment modes are available.
12. As an operator, I want the supervisor to stay unprivileged in both sandboxes, so that I don't have to run the Gateway as root.
13. As an operator, I want the filter sandbox to need no `/usr/bin/bwrap`, so that a minimal image works.
14. As an operator, I want the operator guide to say that the filter sandbox gives up the namespace layer, so that I choose it only when I must.
15. As an operator, I want the configuration reference to describe `worker_sandbox` and both values, so that I can configure it from the reference alone.
16. As an operator, I want the troubleshooting table to cover a worker sandbox startup failure under either sandbox, so that I can fix a refused host.
17. As an operator, I want the log to say when a grant worker was killed by the filter, so that I can tell a sandbox violation from a crash.
18. As a user approving a grant, I want a grant whose worker was killed by the filter to need fresh approval, so that a compromised worker cannot keep serving under my approval.
19. As a security reviewer, I want a grant worker unable to open any file, so that it cannot read the supervisor's credentials or configuration.
20. As a security reviewer, I want a grant worker unable to read the supervisor's environment or memory, so that supervisor secrets stay with the supervisor.
21. As a security reviewer, I want a grant worker unable to read another grant worker's memory, so that one user's traffic keys never reach another user.
22. As a security reviewer, I want a grant worker unable to open TCP connections or send UDP datagrams of its own, so that all egress goes through the supervisor's mediated legs.
23. As a security reviewer, I want a grant worker unable to run programs, so that it cannot escape into a less-confined process.
24. As a security reviewer, I want a grant worker able to signal only itself, so that it cannot stop or kill other grant workers or the supervisor.
25. As a security reviewer, I want a forbidden system call to kill the grant worker rather than fail quietly, so that a compromised worker cannot keep probing.
26. As a security reviewer, I want the allow-list to reject system calls from a foreign ABI (x32 on x86-64, or the wrong architecture), so that the filter cannot be bypassed by calling convention.
27. As a security reviewer, I want ADR 0001 to define what counts as an equivalent OS sandbox under the per-grant isolation contract, so that the contract is checkable.
28. As a security reviewer, I want the same base layers in the namespace sandbox, so that today's deployments also gain the allow-list and non-dumpable memory.
29. As a grant worker, I want to keep receiving my three streams by `SCM_RIGHTS` after confinement, so that the handoff works unchanged.
30. As a grant worker, I want to keep serving concurrent connections on threads after confinement, so that throughput is unchanged.
31. As a Gateway maintainer, I want CI to run the real Gateway under the filter sandbox in a container that refuses namespaces as Fargate does, so that every pull request proves the filter sandbox without AWS.
32. As a Gateway maintainer, I want CI to keep running the real Gateway under the namespace sandbox, so that the allow-list is exercised on every deployment shape.
33. As a Gateway maintainer, I want a missing system call to fail CI, so that a dependency or libc update cannot kill grant workers in production first.
34. As a Gateway maintainer, I want the containment checks to run against the worker sandbox's own interface, so that each property has a direct test.
35. As a Gateway maintainer, I want the containment checks to run with two concurrent stand-in grant workers, so that isolation between users is tested, not assumed.
36. As a Gateway maintainer, I want the glossary to define grant worker, worker sandbox, namespace sandbox and filter sandbox, so that code, docs and issues use one language.
37. As the reporter of #18, I want to qualify the filter sandbox on real Fargate with two concurrent grants, so that Fargate joins the tested platforms on evidence.
38. As an Integrator, I want the Fargate deployment to pass the same end-to-end check as Compose (a paired Companion approves a client certificate and the mock MCP tool reads the mTLS-protected flag), so that I can ship it to my users.
39. As a reader of the design record, I want its platform line to name both worker sandboxes, so that the record matches the product.
40. As a Gateway maintainer, I want to run both test seams on real Fargate, x86-64 and arm64, from a harness kept in the repo, so that a difference in Fargate's kernel shows up on our side before the reporter qualifies.
41. As a Gateway maintainer, I want to rerun that harness for any later release that touches the grant worker, so that Fargate stays qualified as the allow-list changes.

## Implementation Decisions

- **ADR 0001 binds this work.** It is accepted and defines the base layers as the equivalent OS sandbox. The ADR and the first `GLOSSARY.md` are on branch `docs/18-worker-sandbox` and land with this spec's first pull request. Use the glossary's terms: grant worker, worker sandbox, namespace sandbox, filter sandbox.
- **Configuration.** The Gateway configuration gains an optional top-level field `worker_sandbox` with two values, `"namespaces"` and `"filter"`. An omitted field means `"namespaces"`. Any other value fails deserialization, like every unknown field today. Both sidecar and shared mode accept both values.
- **A worker sandbox module in the Gateway library crate**, beside the existing public modules, so that integration tests can reach it. Its interface is one operation: confine the calling process as a grant worker for the given worker sandbox. It reports the layers it applied (allow-list, Landlock ABI or unavailable, non-dumpable), or fails naming the layer that failed. It is the only new public interface.
- **The grant worker confines itself** as the first thing its entry point does, before it reads its control socket or handles any input. That is one code path for both sandboxes. The namespace sandbox launches the grant worker through bubblewrap as today, and the grant worker then applies the base layers inside it. The filter sandbox launches the grant worker directly, with a cleared environment and only the control socket and standard streams open. Running the executable has to happen before confinement, because the allow-list forbids it afterwards.
- **Base layers, applied in this order:**
  1. **Non-dumpable.**
  2. **Landlock:** a rule set handling every access right the kernel's ABI knows, with no rules granted. That means no file access, plus no TCP bind or connect from ABI 4 and scoped signals and abstract sockets from ABI 6. No Landlock is not an error; it is reported as unavailable.
  3. **`no_new_privs`, then the seccomp allow-list.**
- **The allow-list** permits only the system calls a confined grant worker needs: receiving descriptors, reading and writing its streams, threads and their synchronisation, memory management, randomness, clocks, and exiting. Its default action kills the whole process. It first checks the architecture and kills on a mismatch; on x86-64 it also rejects the x32 range. Signals are allowed only when the target is the grant worker itself (`kill` and `tgkill` against its own process ID; `tkill` and `pidfd_send_signal` are denied). The exact list comes from what the tests exercise on x86-64 and arm64, and is kept as small as they allow.
- **The startup probe** launches a real grant worker under the chosen sandbox, as today. The probe worker confines itself and reports its applied layers back over the control socket before exiting. The supervisor logs them. On failure, startup exits with an error of the form `worker sandbox "<sandbox>" failed: <layer>: <cause>`. The error points to the operator guide's section on choosing a worker sandbox and does not suggest the other value.
- **A grant worker killed by the filter.** When a grant worker exits by `SIGSYS`, the supervisor logs that the worker sandbox's filter killed it and fences the grant through the existing worker-failure path, so the grant needs fresh approval.
- **Documentation:**
  - The configuration reference describes `worker_sandbox`.
  - The operator guide gains a section on choosing a worker sandbox: the namespace sandbox is recommended, and the filter sandbox gives up the namespace layer.
  - The troubleshooting row covers both sandboxes.
  - The design record's platform line names both worker sandboxes.
  - The tested-platforms page lists Fargate only after the qualification run.
- **Prototype reference.** The probe on branch `prototype/18-isolation-probe` shows a working seccomp filter, Landlock rule set and `SCM_RIGHTS` handoff under confinement. Its filter is a deny-list, so treat it only as a reference for the mechanics; the product's filter is an allow-list.
- **A Fargate qualification harness, maintained in the repo.** The prototype's CloudFormation stack (ECR repository, a small public VPC, cluster, a `PowerUserPB-`-named execution role with the `PowerUserAccess` boundary, and Fargate 1.4.0 task definitions for X86_64 and ARM64) moves out of the throwaway branch, because every release that touches the grant worker needs it again. It is a qualification tool, not product code: the Gateway never depends on it. It runs the same two test seams as CI, on real Fargate. Running it needs our AWS account and a fresh SSO login, so its ticket is `triage:ready-for-human` unless an agent is given credentials, and it is blocked by the implementation tickets. The prototype's stack, `countersign-isolation-probe-18`, stays deployed until the harness replaces it.
- **Flag: none.** The change ships as an opt-in configuration field. Its default keeps today's behaviour apart from the base layers, which CI proves under the namespace sandbox, and the repository has no release-flag rule.

## Testing Decisions

- **What makes a good test here:** it checks what a grant worker or an operator can observe, not how the filter is written. Assert which actions succeed or are refused, what startup logs and how it fails, and that traffic flows and cutoff holds. Never assert the shape of the allow-list itself.
- **Seam 1: the real Gateway binary, end to end.** Extend the existing runtime test, which runs the real `countersign-gateway serve` against a test grant authority and an mTLS site, with sidecar and shared mode, concurrent users, cutoff and revocation. Run it for each worker sandbox:
  - `"namespaces"` on the CI host, as today. It now also carries the base layers.
  - `"filter"` inside a container under Docker's default security profile, which refuses namespaces as Fargate does.
  - A startup case in that container: `"namespaces"` exits with an error naming the sandbox and the failed layer.
  - Assert that the startup log names the sandbox and its layers.
- **Seam 2: the worker sandbox module.** A new Rust integration test forks two concurrent stand-in grant workers, confines each with the module, and hands each a stream by `SCM_RIGHTS`. It then asserts:
  - the stream arrives, and threads still work;
  - each of these is refused: opening a file, reading the supervisor's environment, reading the supervisor's memory, reading the other worker's memory, TCP connect, UDP send, running a program, and signalling another process;
  - signalling itself works;
  - a forbidden system call kills the worker with `SIGSYS`.

  Run it in both CI environments, the host and the container that refuses namespaces.
- **Both seams on real Fargate, before we ask the reporter.** Docker's default profile reproduces Fargate's refusal but not its kernel (Fargate runs 6.1 with Landlock ABI v2 and Yama scope 1, while CI hosts run newer kernels), and the allow-list depends on the kernel. The qualification harness runs seam 2's containment test and seam 1 under `"filter"` on Fargate 1.4.0, x86-64 and arm64. For seam 1, the test grant authority and mTLS site run inside the task. Passing this run gates asking the reporter to qualify.
- **Prior art:** the runtime test for seam 1. The existing Rust integration tests in the Gateway crate for how to structure seam 2. The prototype's harness for the containment checks.

## Out of Scope

- A separate Fargate task per grant, which would need an authenticated transport in place of descriptor passing.
- Memory and CPU limits per grant worker.
- Changes to how the namespace sandbox isolates beyond adding the base layers.
- Relaxing or removing the fail-closed startup check.
- Changes to the sidecar CA, the issuer or destination policy.
- Qualifying platforms other than Fargate, unless the filter sandbox covers them for free.

## Further Notes

- Origin: #18, a site report from a Fargate deployment, triaged ready-for-human until this design settled the security decision.
- Evidence:
  - The probe ran on Fargate 1.4.0, kernel 6.1.190, x86-64 and arm64, on both the Gateway image and Amazon Linux 2023. bubblewrap was refused, the seccomp filter blocked every check with the handoff intact, and Landlock was ABI v2.
  - Research on primary sources found that Fargate allows only `SYS_PTRACE`, no privileged mode and no custom seccomp profile, and that AWS has no plans to change this (aws/containers-roadmap#1000, closed; #2102, open).
  - [Probe and results](https://github.com/zeroae/countersign/tree/prototype/18-isolation-probe/crates/countersign-gateway/prototype-isolation-probe) · [Fargate capability research](https://github.com/zeroae/countersign/blob/prototype/18-isolation-probe/crates/countersign-gateway/prototype-isolation-probe/research-fargate-capabilities.md) · [ADR 0001](https://github.com/zeroae/countersign/blob/docs/18-worker-sandbox/docs/adr/0001-filter-sandbox-for-hosts-without-namespaces.md) · [Glossary](https://github.com/zeroae/countersign/blob/docs/18-worker-sandbox/GLOSSARY.md)
- Two gates, in order:
  1. Our own run of the qualification harness on Fargate (Testing Decisions) gates asking the reporter.
  2. The reporter's run gates listing Fargate as tested.
- Qualification: the reporter offered to validate on real Fargate with two concurrent grants. The positive end-to-end test is a paired Companion approving a client certificate, then the mock MCP tool reading the mTLS-protected flag into chat. That run gates listing Fargate on the tested-platforms page. It does not gate merging.
- Risk the tests must catch: anything the grant worker loads or calls lazily after confinement, such as unwinding on a panic or a TLS library's first use of randomness, is killed by the allow-list. Seam 1 under both sandboxes is what finds these.
