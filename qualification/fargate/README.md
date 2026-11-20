# Fargate qualification harness

This harness runs the Gateway's two test seams on real ECS Fargate 1.4.0, on x86-64 and arm64, under the [filter sandbox](../../GLOSSARY.md). CI already runs both seams in a container that refuses namespaces as Fargate does (`scripts/filter-sandbox-container.sh`), but on the CI runner's kernel. The filter sandbox's allow-list depends on the kernel, and Fargate runs an older one, so a release that touches the grant worker is qualified here before Fargate stays on the [tested platforms](../../docs/reference/support.md).

It is a qualification tool. The Gateway never depends on it, and nothing here ships.

## What a run proves

Each task runs `qualify.sh` as the Gateway image's user, with Fargate's defaults: no added capability, Fargate's own seccomp profile, no task role. It prints the host's kernel and confinement facts, checks that the host refuses user namespaces and that the image has no bubblewrap, then runs:

1. the worker sandbox containment test (`crates/countersign-gateway/tests/worker_sandbox.rs`);
2. the runtime test under `"filter"` (`crates/countersign-gateway/tests/runtime.py`), with its test grant authority and mTLS site inside the task.

The Gateway's startup line in the log names the layers applied, the Landlock ABI among them. The task exits non-zero at the first step that fails, and `run.sh` exits non-zero when any task did.

The image holds a release build of the commit you run from. Its first log lines name that revision, with `-dirty` when the checkout had uncommitted changes.

## What you need

- Docker with buildx. Neither architecture needs emulation: the images are cross-compiled, and the last stage only copies files.
- The AWS CLI, with credentials that may create the stack. Set `AWS_PROFILE`, and `AWS_REGION` unless the profile names a region. The stack creates one VPC, so pick a region with room for one.
- The execution role is named `PowerUserPB-<stack>-exec` and carries the `PowerUserAccess` permissions boundary, as the `zeroae-code` power-user SSO roles require.

## Deploy, run and tear down

```bash
export AWS_PROFILE=zeroae-code/ZAEPowerUserAccess AWS_REGION=us-east-2
qualification/fargate/run.sh            # deploy the stack, push both images, run both tasks
qualification/fargate/run.sh teardown   # delete the stack, images and logs included
```

One step at a time, or one architecture:

```bash
qualification/fargate/run.sh deploy
qualification/fargate/run.sh build arm64
qualification/fargate/run.sh run arm64
```

`run` prints each task's platform, architecture, image digest and whole log, then its exit code. Record that output on the release's qualification ticket. The stack costs nothing while no task runs, apart from the images' storage, so tear it down or keep it between releases as you prefer. `COUNTERSIGN_QUALIFICATION_STACK` names the stack when you need a second one.

To try the image without AWS, on this host's architecture and under Docker's default profile:

```bash
qualification/fargate/run.sh local
```
