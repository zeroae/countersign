#!/usr/bin/env bash
# Prove the filter sandbox on a host that refuses namespaces, as ECS Fargate
# does: run the Gateway's containment test and its runtime test in a container
# under Docker's default security profile, as an unprivileged user.
#
# Usage: scripts/filter-sandbox-container.sh
# Needs Docker and the Rust toolchain. Builds on this host and runs what it
# built in the container, so the image matches the CI runner's distribution.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build --locked -p countersign-gateway
containment=$(
  cargo test --locked -p countersign-gateway --test worker_sandbox --no-run --message-format=json |
    python3 -c '
import json, sys
for line in sys.stdin:
    message = json.loads(line)
    if message.get("executable") and message["target"]["name"] == "worker_sandbox":
        print(message["executable"])'
)
test -x "$containment"

# Two images. The first has no bubblewrap, so the filter sandbox is shown not
# to need it. The second adds it, so the namespace sandbox fails there because
# the host refuses namespaces, not because a program is missing.
build() {
  docker build --quiet --target "$1" --tag "countersign-filter-sandbox:$1" - <<'EOF'
FROM ubuntu:24.04 AS filter
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl libnss-wrapper python3 python3-pip \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir --break-system-packages cryptography==50.0.2
FROM filter AS namespaces
RUN apt-get update && apt-get install -y --no-install-recommends bubblewrap && rm -rf /var/lib/apt/lists/*
EOF
}
build filter
build namespaces

# No --privileged, --cap-add or --security-opt: Docker's default profile.
# The checkout is mounted where it is on this host, because the containment
# test holds the Gateway executable's path from its build.
inside() {
  local image=$1
  shift
  docker run --rm --user "$(id -u):$(id -g)" --volume "$PWD:$PWD:ro" --workdir "$PWD" \
    "countersign-filter-sandbox:$image" "$@"
}
runtime=(timeout 120 python3 crates/countersign-gateway/tests/runtime.py target/debug/countersign-gateway)

echo '== The container refuses namespaces'
if inside namespaces bwrap --unshare-all --ro-bind / / -- /usr/bin/true; then
  echo 'This container can create namespaces, so it proves nothing about the filter sandbox.' >&2
  exit 1
fi
if inside filter test -e /usr/bin/bwrap; then
  echo 'The image for the filter sandbox has bubblewrap.' >&2
  exit 1
fi

echo '== Worker sandbox containment test'
inside filter timeout 120 "$containment"

echo '== Runtime test under the filter sandbox, without bubblewrap'
inside filter "${runtime[@]}" --worker-sandbox filter

echo '== The namespace sandbox fails at startup with the named error'
inside namespaces "${runtime[@]}" --worker-sandbox namespaces --startup-fails

# The other direction. This one container leaves Docker's default profile for
# one that refuses a single call of the Landlock layer and allows the rest, in
# the image that has bubblewrap: the filter sandbox has to fail by name there,
# and not start grant workers some other way.
echo '== The filter sandbox fails at startup with the named error'
profile=$(mktemp)
trap 'rm -f "$profile"' EXIT
cat >"$profile" <<'EOF'
{"defaultAction": "SCMP_ACT_ALLOW",
 "syscalls": [{"names": ["landlock_restrict_self"], "action": "SCMP_ACT_ERRNO", "errnoRet": 22}]}
EOF
docker run --rm --user "$(id -u):$(id -g)" --volume "$PWD:$PWD:ro" --workdir "$PWD" \
  --security-opt "seccomp=$profile" countersign-filter-sandbox:namespaces \
  "${runtime[@]}" --worker-sandbox filter --startup-fails
