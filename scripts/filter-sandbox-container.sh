#!/usr/bin/env bash
# Prove the filter sandbox on a host that refuses namespaces, as ECS Fargate
# does: run the Gateway's containment test and its runtime test in a container
# under Docker's default security profile, as an unprivileged user. Three last
# steps each use a profile with one quirk instead: a host that refuses the
# allow-list, a kernel without Landlock, and a kernel without close_range.
#
# Usage: scripts/filter-sandbox-container.sh
# Needs Docker and the Rust toolchain. Builds on this host and runs what it
# built in the container, so the image matches the CI runner's distribution.
set -euo pipefail
cd "$(dirname "$0")/.."

# The executable cargo builds for one target of the Gateway crate: the program
# itself, or with `test` the target's tests. A test's build lists the program
# beside it, which the test runs.
built() {
  local tests=False
  [ "$1" = test ] && tests=True
  cargo "$@" --locked -p countersign-gateway --message-format=json | python3 -c '
import json, sys
found = [message["executable"] for message in map(json.loads, sys.stdin)
         if message.get("executable") and message["profile"]["test"] is '"$tests"']
assert len(found) == 1, found
print(found[0])'
}
gateway=$(built build --bin countersign-gateway)
containment=$(built test --no-run --test worker_sandbox)
units=$(built test --no-run --bin countersign-gateway)
target=$(cargo metadata --locked --no-deps --format-version 1 |
  python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')

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

# With `profile` empty: no --privileged, --cap-add or --security-opt, which is
# Docker's default profile. The checkout and cargo's target directory are
# mounted where they are on this host, because the containment test holds the
# Gateway executable's path from its build.
profile=()
inside() {
  local image=$1
  shift
  docker run --rm --user "$(id -u):$(id -g)" --workdir "$PWD" \
    --volume "$PWD:$PWD:ro" --volume "$target:$target:ro" \
    "${profile[@]}" "countersign-filter-sandbox:$image" "$@"
}
# A profile that allows every system call but the one these rules refuse, for
# the steps that need a host with one quirk.
rules=$(mktemp)
trap 'rm -f "$rules"' EXIT
refusing() {
  printf '{"defaultAction": "SCMP_ACT_ALLOW", "syscalls": [%s]}\n' "$1" >"$rules"
  profile=(--security-opt "seccomp=$rules")
}
runtime=(timeout 120 python3 crates/countersign-gateway/tests/runtime.py "$gateway")

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
inside namespaces "${runtime[@]}" --worker-sandbox namespaces --startup-fails namespaces

# The other direction, in the image that has bubblewrap: where the host
# refuses the allow-list, the filter sandbox has to fail by name, and not
# start grant workers some other way. 22 is both PR_SET_SECCOMP and EINVAL.
echo '== The filter sandbox fails at startup with the named error'
refusing '{"names": ["prctl"], "action": "SCMP_ACT_ERRNO", "errnoRet": 22,
           "args": [{"index": 0, "value": 22, "op": "SCMP_CMP_EQ"}]}'
inside namespaces "${runtime[@]}" --worker-sandbox filter --startup-fails 'seccomp allow-list'

# A kernel before 5.13, or one built without Landlock, answers ENOSYS. The
# filter sandbox starts there with its other layers, and says so.
echo '== The filter sandbox starts on a kernel without Landlock'
refusing '{"names": ["landlock_create_ruleset"], "action": "SCMP_ACT_ERRNO", "errnoRet": 38}'
inside filter "${runtime[@]}" --worker-sandbox filter --landlock unavailable

# Linux before 5.11 cannot mark every descriptor close-on-exec in one call.
# 38 is ENOSYS, as such a kernel answers.
echo '== The filter sandbox passes on no descriptor on a kernel without close_range'
refusing '{"names": ["close_range"], "action": "SCMP_ACT_ERRNO", "errnoRet": 38}'
inside filter timeout 60 "$units" filter_sandbox_launch
