# Countersign

Desktop approval for HTTPS Workloads that use an installed client certificate. The design record, `docs/specs/2026-11-17-countersign-design.md`, defines the rest of the language until it moves here.

## Language

### Gateway isolation

**Grant worker**:
The short-lived, low-privilege process the Gateway supervisor starts for one grant version, which carries that grant's traffic and nothing else.
_Avoid_: worker process, child, sandbox

**Worker sandbox**:
The OS isolation around every grant worker, chosen by the operator, that keeps it from the supervisor's credentials, other grant workers and the network.
_Avoid_: sandbox mode, isolation level

**Namespace sandbox**:
The default worker sandbox: the filter sandbox's guarantees plus a separate view of the filesystem, processes and network for each grant worker.
_Avoid_: bubblewrap mode, bwrap sandbox

**Filter sandbox**:
The worker sandbox for hosts that cannot give a grant worker its own namespaces, where the kernel refuses every action a grant worker does not need.
_Avoid_: seccomp mode, seccomp sandbox, fallback sandbox
