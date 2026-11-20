---
status: accepted
date: 2026-11-19
supersedes: none
---

# A filter sandbox for hosts without namespaces

The per-grant isolation contract in the design record asks for grant workers isolated "by user principal/container or equivalent OS sandbox, including between concurrent users". v0.2.0 meets it only with bubblewrap, which needs unprivileged user namespaces. ECS Fargate refuses those to every task (#18), and AWS has said it has no plans to allow it. We add a second worker sandbox, the **filter sandbox**, and define it as the equivalent OS sandbox for hosts that cannot create namespaces.

## Decision

1. **Every grant worker gets the same base layers**, in both worker sandboxes:
   - a seccomp allow-list of the system calls a grant worker needs once it holds its streams;
   - Landlock, at whatever ABI the kernel offers. It is a backstop: the Gateway logs the ABI it got and still starts without Landlock;
   - non-dumpable, so no other process of the same user can read its memory;
   - no inherited descriptors, environment or secret address space.
2. **The namespace sandbox** adds namespaces on top: the worker's own filesystem, process and network view, supplied by bubblewrap. It stays the default and the recommendation wherever the host allows it.
3. **The filter sandbox** is the base layers alone. It is allowed in sidecar and shared mode, because the base layers keep concurrent users' grant workers apart.
4. **The operator chooses explicitly**: Gateway field `worker_sandbox`, `"namespaces"` (default) or `"filter"`. The Gateway never falls back from one to the other. Startup probes the chosen sandbox and fails closed. The error names the sandbox and the layer that failed, and points to the operator guide rather than suggesting the other sandbox.
5. **A system call outside the allow-list kills the grant worker.** The supervisor logs the cause and fences the grant like any other worker failure, so the grant needs fresh approval.
6. **A grant worker may signal only itself.** Without a PID namespace, every grant worker runs as the same user as the other workers and the supervisor, so the allow-list checks each signal's target.

## Evidence

A throwaway probe confined a stand-in worker, handed it a stream by `SCM_RIGHTS` as the Gateway does, and tried what a compromised worker would try. On Fargate 1.4.0 (kernel 6.1.190, x86-64 and arm64, Gateway and Amazon Linux 2023 images), bubblewrap was refused. A task-installed seccomp filter blocked files, the supervisor's environment and memory, other workers' memory, TCP, UDP and running programs, and the stream handoff kept working. Landlock was ABI v2, which covers files and running programs but not the network. [Probe and results](https://github.com/zeroae/countersign/tree/8ab4a7f2f5214eb6439e0d40de5b0fbc0fd24ae5/crates/countersign-gateway/prototype-isolation-probe) · [Fargate capability research](https://github.com/zeroae/countersign/blob/8ab4a7f2f5214eb6439e0d40de5b0fbc0fd24ae5/crates/countersign-gateway/prototype-isolation-probe/research-fargate-capabilities.md)

## Considered options

- **Fall back automatically** from the namespace sandbox to the filter sandbox. Rejected: a kernel or container-profile change would quietly weaken isolation on every grant worker.
- **A separate user per grant worker.** Rejected: switching users needs a root-started supervisor, against the operator guide's "keep the supervisor unprivileged", and Fargate refuses it anyway.
- **Landlock as the main mechanism.** Rejected: Fargate's ABI v2 does not cover the network, and no ABI covers UDP.
- **A separate Fargate task per grant.** Rejected for now: the handoff passes descriptors, so a remote worker would need a new authenticated transport.
- **Return an error on a forbidden call** instead of killing the worker. Rejected: a grant worker never needs one, so hitting one is a bug or an attack, and either should end the grant.

## Consequences

- The filter sandbox gives up the namespace layer. The operator guide and configuration reference say so, and the design record's platform line changes from "requires bubblewrap and unprivileged user namespaces" to name both worker sandboxes.
- The allow-list now runs on every deployment, so a system call a grant worker newly needs (a dependency update, a new libc) kills workers everywhere until it is added. Tests must exercise the real worker under the filter.
- Fargate joins the tested platforms only after a real run with two concurrent grants, in which a paired Companion approves a client certificate and the mock MCP tool reads the mTLS-protected flag.
