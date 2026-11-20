#!/bin/sh
# Runs inside the qualification image, as the task's only command: says what
# host this is, then runs the Gateway's containment test and its runtime test under the
# filter sandbox. Exits non-zero at the first step that fails.
set -eu

fact() { printf '%s: %s\n' "$1" "$2"; }
status() { sed -n "s/^$1:[[:space:]]*//p" /proc/self/status; }

echo '== Host'
fact 'Countersign revision' "$COUNTERSIGN_REVISION"
fact 'Kernel' "$(uname -r) $(uname -m)"
fact 'uid / gid' "$(id -u) / $(id -g)"
fact 'CapEff' "$(status CapEff)"
fact 'NoNewPrivs' "$(status NoNewPrivs)"
fact 'Seccomp' "$(status Seccomp)"
fact 'Yama ptrace_scope' "$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo unreadable)"
fact 'LSMs' "$(cat /sys/kernel/security/lsm 2>/dev/null || echo unreadable)"

echo '== The host refuses namespaces'
# Without the program, its failure would say nothing about the host.
command -v unshare >/dev/null || { echo 'The qualification image has no unshare.' >&2; exit 1; }
if unshare --user true 2>/dev/null; then
  echo 'This host can create user namespaces, so it proves nothing about the filter sandbox.' >&2
  exit 1
fi
if command -v bwrap >/dev/null; then
  echo 'The qualification image has bubblewrap.' >&2
  exit 1
fi
echo 'refused, and the image has no bubblewrap'

echo '== Worker sandbox containment test'
timeout 300 worker-sandbox-containment

# The Gateway's startup log, which this prints, names the worker sandbox and
# each layer applied, the Landlock ABI among them.
echo '== Runtime test under the filter sandbox'
timeout 300 python3 /qualification/runtime.py "$(command -v countersign-gateway)" --worker-sandbox filter

echo '== Qualified: the containment test and the runtime test passed under the filter sandbox'
