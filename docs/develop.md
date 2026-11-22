# Develop and release

The Cargo workspace contains the protocol, PKI validation, Broker, Gateway and native addon. The pnpm workspace contains the Electron Companion, web widget and demo Integrator. Use the Rust toolchain pinned in `rust-toolchain.toml`, Node 24 and pnpm 10.28.2. On Ubuntu install `libnss3-dev` for native builds and `bubblewrap` for Gateway runtime tests.

## Build the Companion

From the checkout root, run the following on the same OS and architecture as the Electron executable you intend to use.

```sh
pnpm install --frozen-lockfile
cargo build --locked -p countersign-native
node scripts/native-package.mjs debug
pnpm --filter @countersign/companion exec electron-builder --dir --publish never
```

The staging script copies the host's production addon and checks its exported functions. The unpacked app is under `packages/companion/dist/`. On Linux, the executable is `linux-unpacked/countersign-companion` on x64 or `linux-arm64-unpacked/countersign-companion` on ARM64. Pass that executable to the [demo launcher](try.md). To produce the host's installer, build the crate with `--release`, run `node scripts/native-package.mjs`, then run `pnpm --filter @countersign/companion package`.

## Run the checks

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
pnpm lint
pnpm test
```

### The pre-commit hook

A tracked pre-commit hook, `.githooks/pre-commit`, runs fast checks on what you stage. It refuses a commit when a staged Rust file is not formatted as `cargo fmt` would format it, and when a staged JavaScript file that `pnpm lint` covers fails ESLint: the packages' `src` and `test` folders and the demo Integrator. It checks the staged copy of each file, not the one in your working tree. When `node_modules` is missing it skips ESLint and says so. It finishes in well under a second. It runs no build, no test suite and no network call. Clippy, the test suites and the Gateway's runtime test run in the [CI workflow](https://github.com/zeroae/countersign/blob/main/.github/workflows/ci.yml) and the end-to-end workflow.

A Claude session installs the hook when it starts, through the `SessionStart` hook in `.claude/settings.json`. Without Claude, install it once per clone from the checkout root:

```sh
scripts/install-git-hooks.sh
```

The script sets `core.hooksPath` to `.githooks`. That setting covers every worktree of the clone, and each worktree runs its own tracked copy of the hook. If `core.hooksPath` already points elsewhere, or the clone's `.git/hooks` folder holds hooks of its own, which `core.hooksPath` would stop running, the script changes nothing and says so. To skip the hook for one commit, run `git commit --no-verify`. The tests for the hook and the script are in `scripts/test_git_hooks.py`:

```sh
python3 -m unittest discover -s scripts -p 'test_git_hooks.py'
```

To run the Gateway's tests under the filter sandbox on a host that refuses namespaces, run `scripts/filter-sandbox-container.sh`, which needs Docker. It runs the containment test and the runtime test in a container under Docker's default security profile, as the end-to-end workflow's `gateway-filter-sandbox` job does. Its two last steps use a profile with one quirk each: where the host refuses the allow-list, the filter sandbox has to fail at startup by name, and where the kernel has no `close_range`, a grant worker still has to start with no descriptor of the supervisor's.

That container has the CI runner's kernel. To run the same two tests on real ECS Fargate 1.4.0, x86-64 and arm64, use the qualification harness, `qualification/fargate/run.sh`. It needs our AWS account, and its [README](https://github.com/zeroae/countersign/blob/main/qualification/fargate/README.md) says how to deploy, run and tear it down. Run it for every release that touches the grant worker.

For the graphics and network path, run the [demo walkthrough](try.md) with `--verify` to automate the installed Companion and browser. The hosted end-to-end job also runs a separate harness that selects identities from candidate lists of different sizes, verifies the peer fingerprint and checks revocation. The native qualification jobs generate identities in disposable provider stores. On macOS and Windows use a disposable runner account for that harness because it changes user-level keychain or certificate-store state. [End-to-end workflow](https://github.com/zeroae/countersign/blob/fbb5aa7c951f8b70a238f3351140aa44a6184adf/.github/workflows/e2e.yml) · [Native qualification workflow](https://github.com/zeroae/countersign/blob/fbb5aa7c951f8b70a238f3351140aa44a6184adf/.github/workflows/native.yml)

### Qualify the Gateway against a real Squid

The demo launcher's Squid variant puts a real Squid between the Gateway and the site, as the Gateway's [egress proxy](operate.md#reach-sites-through-an-egress-proxy). Run it by hand before a release that touches the Gateway's route to a site; no workflow runs it. It needs what the [demo walkthrough](try.md) needs, with the same virtual environment, and pulls the Squid image. From the checkout root, on a desktop session:

```sh
.venv/bin/python examples/demo-integrator/compose_demo.py --squid --verify \
  --app "$PWD/packages/companion/dist/linux-arm64-unpacked/countersign-companion"
```

Without a desktop session, run it under a virtual display, as the end-to-end workflow runs its harness: `dbus-run-session -- xvfb-run -a .venv/bin/python examples/demo-integrator/compose_demo.py --squid --verify --app ...`. Without `--verify` the variant runs the interactive walkthrough through Squid.

`--squid` layers `compose.squid.yaml` over the default `compose.yaml`, which it leaves unchanged. The Gateway shares the backend network with the Broker and Squid, and the site moves to a network only Squid shares. The site runs in the network of a placeholder container, `site-host`, so stopping the site leaves its name and address in place, as for a site whose server is down. The Gateway's configuration names `http://squid:3128` as its `egress_proxy`, and its rule for the site has no `private_networks`. Squid allows `CONNECT` only to `site.test:9444` on the site's address, refuses that name when any of its addresses is another, blocks metadata, link-local and loopback addresses, and does no TLS interception: its configuration is `examples/demo-integrator/squid.conf`.

`--verify` drives the real Companion and browser, as for the default walkthrough, and fails on the first check that does not hold. Before the approval it checks that the Gateway logged the egress proxy and that it can neither resolve `site.test` nor connect to the site's address. From the approved request it correlates Squid's access log line `TCP_TUNNEL/200` for `CONNECT site.test:9444` to the site's address, the fingerprint the site returned, which must equal the one approved in the Companion, and the response the Workload read. Then, with that grant still live and no second approval, the Workload repeats its request three times. Each must end in 502 with the `Countersign-Error` below, and the Gateway must log it under the same `Countersign-Request-ID`.

| Step | `Countersign-Error` | What Squid logs |
| --- | --- | --- |
| The launcher swaps Squid's rule to refuse the site and reconfigures it | `proxy_denied` | `TCP_DENIED/403` with `HIER_NONE`: it opened no connection to the site |
| It restores the rule and stops the site | `upstream_failure` | `TCP_TUNNEL/503`: the site's address refused the connection |
| It stops Squid | `proxy_unavailable` | Nothing |

The variant was qualified against Squid 6.14, as `squid -v` reports it, from the image `ubuntu/squid:6.6-24.04_edge@sha256:d9c34c5ab74c6dd41cf1070d9b4221aac072e67e983527ca2d41512958f77506`, on Linux arm64. The tag names Ubuntu's original Squid version; the image's package is newer. `compose.squid.yaml` pins that digest. To qualify another Squid, change the image there, run the variant and record the version the run prints on its `Egress proxy:` line here.

## A grant worker died of SIGSYS

The worker sandbox's filter kills a grant worker with `SIGSYS` when it makes a system call outside the allow-list, or a listed call with an argument the list refuses. One call is the exception: `clone3` fails as unsupported and kills nothing. The Gateway logs `grant worker killed by the worker sandbox's filter (SIGSYS); grant fenced`, which does not say which call it was. Two commands do.

The kernel writes an audit line for each filter kill, under either worker sandbox. Reading it needs no root where your user can read the system journal, as members of `adm` or `systemd-journal` can.

```sh
journalctl -k | grep type=1326
```

```text
kernel: audit: type=1326 audit(1795144504.852:6342): ... pid=2188053 comm="worker_sandbox-" exe=".../target/debug/deps/worker_sandbox-dcf0f669f7f13f3c" sig=31 arch=c00000b7 syscall=56 compat=0 ip=0xec5e8e3f07c4 code=0x80000000
```

`sig=31` is `SIGSYS`, `syscall=` is the number of the call and `arch=` the architecture that number belongs to: `c000003e` is x86-64 and `c00000b7` is arm64. The line above is not a grant worker's. It comes from the containment test in `crates/countersign-gateway/tests/worker_sandbox.rs`, which has the filter kill a process on purpose many times in each run, and `comm="worker_sandbox-"` marks every such line. Leave those out: a grant worker's line names another `comm` and `exe`.

In CI the same lines come from `sudo dmesg`, which the CI and end-to-end workflows print when a run fails, in the step "Name the system call when the worker sandbox's filter killed a grant worker". A host that runs the audit daemon, `auditd`, sends these lines to `/var/log/audit/audit.log` and keeps them out of the journal.

When the number is not enough, trace the Gateway. The runtime test takes the Gateway executable as its argument, so give it a wrapper that starts the real one under `strace`. Besides `strace`, the test needs what its first lines list: bubblewrap, libnss-wrapper, curl and Python's `cryptography`. From the checkout root:

```sh
cat > /tmp/traced-gateway <<'EOF'
#!/bin/sh
exec strace -D -f -o "/tmp/gateway-trace.$$" "$PWD/target/debug/countersign-gateway" "$@"
EOF
chmod +x /tmp/traced-gateway
python3 crates/countersign-gateway/tests/runtime.py /tmp/traced-gateway
```

The wrapper runs `strace -D -f -o <file> target/debug/countersign-gateway serve <config>` for each Gateway the test starts, one trace file per Gateway. `-f` follows the Gateway into its grant workers. `-D` matters: the sidecar part of the runtime test stops every descendant of the process it started. Without `-D` that process is `strace` and the Gateway is its child, so the test stops the Gateway and hangs. With `-D` the Gateway is the process the test started, and the tracer runs outside its process tree. Tracing slows the Gateway, so one of the test's timing assertions can fail under it. The trace up to that point is still complete.

In each trace file, search for `+++ killed by SIGSYS +++`. A filter kill ends every thread of the grant worker, so the file has one such line for each thread, and for most of them the line above is an allowed call the thread was waiting in. Look in the lines before the first of them for the call the audit line named. The trace shows its arguments and what the grant worker did before it; ignore the result `strace` prints for it. The last Gateway the test starts has one grant worker the test itself kills, marked `--- SIGSYS {si_signo=SIGSYS, si_code=SI_USER, ...} ---`. That one is not a filter kill.

The same number is a different call on each architecture, so map it with the architecture from the audit line. `ausyscall` takes both:

```sh
ausyscall aarch64 56   # openat
ausyscall x86_64 56    # clone
```

`ausyscall` comes in the `auditd` package, and installing that starts the audit daemon, which takes the audit lines out of the journal as above. Without it, read the kernel's table for the architecture of the killed grant worker, which need not be the machine you are reading on: [`syscall_64.tbl`](https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl) for x86-64 and [`asm-generic/unistd.h`](https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/unistd.h) for arm64. A host of the same architecture has it installed, as `/usr/include/x86_64-linux-gnu/asm/unistd_64.h` on x86-64 and `/usr/include/asm-generic/unistd.h` on arm64, where `grep -w 56` finds `#define __NR_openat 56`.

A call a grant worker needs goes in the allow-list in `crates/countersign-gateway/src/worker_sandbox.rs`, with the reason beside it as a comment: `ALLOWED` for a call allowed whatever its arguments, or `conditional`, in `allow_list`, for a call allowed only with certain arguments. When the killed call is already in `conditional`, an argument failed its test, and the trace shows which. A call a grant worker should not make is a bug in the grant worker, not a gap in the list.

## Install with conda on Linux

On a Linux desktop with rattler-build and conda installed, place the local channel outside the checkout. Build, install and start the packaged application in the graphical login session.

```sh
rattler-build build --recipe recipe/recipe.yaml --output-dir "$HOME/.cache/countersign-conda-output" -c conda-forge
conda create -n countersign-local -c "file://$HOME/.cache/countersign-conda-output" -c conda-forge countersign-companion
conda run -n countersign-local countersign-companion
```

The recipe installs Electron, the launcher and the matching native addon. A future conda-forge submission needs a versioned release source with its checksum. [Recipe and package tests](https://github.com/zeroae/countersign/blob/main/recipe/recipe.yaml)

## Preview and edit the handbook

Use Python 3.12 and the pinned documentation requirements.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-docs.txt
.venv/bin/python -m mkdocs build --strict
.venv/bin/python -m mkdocs serve
```

The build writes a static site in `site/`. Version tags add a handbook snapshot to the `gh-pages` branch and deploy the archive to [GitHub Pages](https://zeroae.github.io/countersign/). Use the version selector for an exact release. For example, `/0.1.0/` stays at that release, `/0.1/` follows stable patches in the 0.1 series, and `/latest/` follows the newest stable release. Unversioned handbook links open the latest stable page. The documentation workflow runs the strict build on documentation PRs and attaches a `countersign-handbook` artifact. To read a downloaded artifact, extract it and run `python3 -m http.server --bind 127.0.0.1` from the directory containing `index.html`.

Diagrams live in `docs/assets/diagrams/`, each with a light and a `-dark` variant. The architecture and deployment diagrams are hand-edited SVGs; the two sequence diagrams have Mermaid sources (`.mmd`). Every colour comes from `palette.json`. The hand-edited SVGs reference it only through `var(--token)`, and the Mermaid sources and `theme.json` name tokens as `{token}`, for example `rect {band-request}`. The script stops on any other colour. Edit the light SVG or the `.mmd` source, then regenerate both variants from the checkout root. Mermaid export needs Node and a Chromium that Puppeteer can launch; set `PUPPETEER_EXECUTABLE_PATH` to reuse an installed one.

```sh
python3 scripts/render_diagrams.py
```

The pages embed both variants with the `#gh-light-mode-only` and `#gh-dark-mode-only` suffixes, which GitHub and the handbook's theme toggle both honour. The original [design and decision record](https://github.com/zeroae/countersign/blob/fbb5aa7c951f8b70a238f3351140aa44a6184adf/docs/specs/2026-11-17-countersign-design.md) remains available to contributors.

### Screenshots

Screenshots are rendered, not captured by hand. `scripts/capture_screenshots.mjs` loads the real Companion renderer and the demo Integrator page in Playwright's Chromium. A stubbed `window.countersign` API and fixture `/api` responses supply the data, so no Broker, Gateway or certificate store is involved. The clock, locale and time zone are fixed, and every shot is taken at twice its CSS size. The demo page is captured in light and dark; the Companion has no dark theme yet. From the checkout root, after `pnpm install`:

```sh
pnpm exec playwright install chromium   # once
pnpm screenshots
```

The script writes raw captures and `boxes.json`, the CSS-pixel box of each highlighted element, to `docs/assets/screenshots/raw/`. `scripts/annotate_screenshots.py`, run by the same command, reads those boxes and draws the callouts onto the copies the pages embed. Change the fixtures or selectors in the capture script and the labels in the annotation script, then look at every changed image before committing. Set `CHROMIUM_PATH` or pass `--browser` to use another Chromium build, and `--only widget,job-result` to recapture a few shots. Every shot has a `-dark` twin, the Companion's included. Embed both with the `#gh-light-mode-only` and `#gh-dark-mode-only` suffixes, as for diagrams. The Companion shots render `packages/companion/src` with a stubbed `window.countersign`; extend the stub when the preload API changes. CI does not run the capture.

## What CI and release tags produce

Pushes run workspace and native checks on Linux and Windows. Pull requests and version releases also run macOS jobs. Distribution jobs on PRs build unsigned desktop installers, validate the bundled addon with Electron, and build the two container targets. See the [tested platforms](reference/support.md) for the runs behind each claim.

Version tags matching `v*` trigger desktop builds, native prebuilds, GitHub release assets with `SHA256SUMS`, and the two GHCR images tagged with the release name. The image names are `ghcr.io/zeroae/countersign-gateway` and `ghcr.io/zeroae/countersign-broker`. Windows signing and macOS signing and notarization require the repository variable `COUNTERSIGN_SIGN_RELEASES=true` and the corresponding release secrets. A signed release still needs qualification on its intended operating systems. The conda recipe builds a local channel. [Release workflow and required secrets](https://github.com/zeroae/countersign/blob/fbb5aa7c951f8b70a238f3351140aa44a6184adf/.github/workflows/distribution.yml)

## Publish to crates.io and npm

A version tag publishes the five Rust crates `countersign-protocol`, `countersign-pki`, `countersign-native`, `countersign-broker` and `countersign-gateway`, plus the browser package `@zeroae/countersign-widget`. All six carry the MIT License. Electron installers and native prebuilds remain GitHub release assets. [Registry workflow](https://github.com/zeroae/countersign/blob/main/.github/workflows/publish.yml)

### Set up the first release

The GitHub environments `crates.io` and `npm` accept deployments from tags matching `v*`. Add each bootstrap credential under **Settings → Environments** in the named environment.

1. Sign in to crates.io and verify your email. Create a short-lived API token with permission to publish **new crates** and new versions of the five crate names. Store it as `CRATES_IO_BOOTSTRAP_TOKEN` in the GitHub `crates.io` environment. The first successful upload establishes ownership of each name. [Cargo publishing guide](https://doc.rust-lang.org/cargo/reference/publishing.html)
2. Sign in to npm with an account authorized to create public packages in the `@zeroae` scope. For the first release, create a short-lived granular token with read/write access to packages in that scope and **Bypass two-factor authentication** enabled for CI. Save it as `NPM_BOOTSTRAP_TOKEN` in the GitHub `npm` environment. [npm access tokens](https://docs.npmjs.com/about-access-tokens/)

### Cut a release

Set the workspace version and internal dependency requirements in `Cargo.toml` and the version in `packages/widget/package.json`. Refresh and commit `Cargo.lock` with the version changes. From the reviewed commit, push the matching tag (for example, `v0.1.0`). The registry workflow checks that tag against every public package before either upload job starts. It builds the Rust archives, tests the widget and loads both exports from an installation of the npm tarball. Pull requests and release tags both run the Rust workspace tests on the release runner.

Cargo uploads dependencies before their consumers. npm publishes the tested tarball with provenance and uses `latest` for stable releases and `next` for prereleases such as `v0.2.0-rc.1`. If an upload fails, rerun the failed job on the same tag. Each registry job checks existing versions against the tested archives and skips matching uploads. A checksum conflict requires investigation before continuing.

If a failure requires a workflow fix after the release tag is public, merge the fix and push a tag named `registry-retry/vX.Y.Z` at the fixed commit. Permit that exact retry tag in both registry environments. The workflow fetches the original `vX.Y.Z` tag, pins the upload jobs to its commit, and checks that the workflow revision contains the same widget sources for npm provenance. Desktop and container distribution continues to use the original release tag.

### Switch to trusted publishing

After the first release, add a GitHub Actions trusted publisher in the settings of **each crate** and the **npm widget**. Use owner `zeroae`, repository `countersign`, workflow filename `publish.yml`, and the environment below.

| Registry | GitHub environment | Publisher permissions |
| --- | --- | --- |
| crates.io | `crates.io` | Configure the publisher for each of the five crates. |
| npm | `npm` | Allow direct `npm publish` for `@zeroae/countersign-widget`. |

Delete the bootstrap secrets from GitHub and revoke both temporary tokens at their registries. Subsequent tags authenticate with the GitHub job's short-lived OIDC identity. Set up the npm publisher within two days of its first OIDC release, or recreate the configuration if it expires. [crates.io trusted publishing](https://crates.io/docs/trusted-publishing) · [npm trusted publishing](https://docs.npmjs.com/trusted-publishers/)

The desktop distribution workflow packs the native installer on each of the six release runners and installs its npm archive into a clean consumer project. It checks the installed payload against the original binary. On a release, `distribution.yml` publishes the six `@zeroae/countersign-{linux,darwin,win32}-{x64,arm64}` packages before `@zeroae/countersign`. For trusted publishing, configure those seven npm packages with workflow filename `distribution.yml` and environment `npm`. The widget uses `publish.yml`.
