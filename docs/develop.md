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

For the graphics and network path, run the [demo walkthrough](try.md) with `--verify` to automate the installed Companion and browser. The hosted end-to-end job also runs a separate harness that selects identities from candidate lists of different sizes, verifies the peer fingerprint and checks revocation. The native qualification jobs generate identities in disposable provider stores. On macOS and Windows use a disposable runner account for that harness because it changes user-level keychain or certificate-store state. [End-to-end workflow](https://github.com/zeroae/countersign/blob/fbb5aa7c951f8b70a238f3351140aa44a6184adf/.github/workflows/e2e.yml) · [Native qualification workflow](https://github.com/zeroae/countersign/blob/fbb5aa7c951f8b70a238f3351140aa44a6184adf/.github/workflows/native.yml)

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

The build writes a static site in `site/`. The documentation workflow runs the strict build on documentation PRs and attaches a `countersign-handbook` artifact. To read a downloaded artifact, extract it and run `python3 -m http.server --bind 127.0.0.1` from the directory containing `index.html`.

The architecture and deployment diagrams are editable SVGs in `docs/assets/diagrams/`. The two sequence diagrams have Mermaid sources in the same directory. To regenerate the first-request sequence, run this from the checkout root with Chromium available to Mermaid CLI.

```sh
npx --yes --package=@mermaid-js/mermaid-cli@11.12.0 mmdc \
  -i docs/assets/diagrams/first-request.mmd \
  -o docs/assets/diagrams/first-request.svg \
  -c docs/assets/diagrams/theme.json -I first-request -b white -q
```

Use `access-ends` for the lease timeline. Both GitHub and the static handbook display the exported SVG directly. Capture UI changes from a packaged Companion paired to a disposable demo account. Confirm the selected certificate against the peer fingerprint before updating the walkthrough. The original [design and decision record](https://github.com/zeroae/countersign/blob/fbb5aa7c951f8b70a238f3351140aa44a6184adf/docs/specs/2026-11-17-countersign-design.md) remains available to contributors.

## What CI and release tags produce

Pushes run workspace and native checks on Linux and Windows. Pull requests and version releases also run macOS jobs. Distribution jobs on PRs build unsigned desktop installers, validate the bundled addon with Electron, and build the two container targets. See the [tested platforms](reference/support.md) for the runs behind each claim.

Version tags matching `v*` trigger desktop builds, native prebuilds, GitHub release assets with `SHA256SUMS`, and the two GHCR images tagged with the release name. The image names are `ghcr.io/zeroae/countersign-gateway` and `ghcr.io/zeroae/countersign-broker`. Windows signing and macOS signing and notarization require the repository variable `COUNTERSIGN_SIGN_RELEASES=true` and the corresponding release secrets. A signed release still needs qualification on its intended operating systems. The conda recipe builds a local channel. [Release workflow and required secrets](https://github.com/zeroae/countersign/blob/fbb5aa7c951f8b70a238f3351140aa44a6184adf/.github/workflows/distribution.yml)

## Publish to crates.io and npm

A version tag publishes the five Rust crates `countersign-protocol`, `countersign-pki`, `countersign-native`, `countersign-broker` and `countersign-gateway`, plus the browser package `@zeroae/countersign-widget`. All six carry the MIT License. Electron installers and native prebuilds remain GitHub release assets. [Registry workflow](https://github.com/zeroae/countersign/blob/main/.github/workflows/publish.yml)

### Set up the first release

The GitHub environments `crates-io` and `npm` accept deployments from tags matching `v*`. Add each bootstrap credential under **Settings → Environments** in the named environment.

1. Sign in to crates.io and verify your email. Create a short-lived API token with permission to publish **new crates** and new versions of the five crate names. Store it as `CRATES_IO_BOOTSTRAP_TOKEN` in the GitHub `crates-io` environment. The first successful upload establishes ownership of each name. [Cargo publishing guide](https://doc.rust-lang.org/cargo/reference/publishing.html)
2. Sign in to npm with an account authorized to create public packages in the `@zeroae` scope. For the first release, create a short-lived granular token with read/write access to packages in that scope and **Bypass two-factor authentication** enabled for CI. Save it as `NPM_BOOTSTRAP_TOKEN` in the GitHub `npm` environment. [npm access tokens](https://docs.npmjs.com/about-access-tokens/)

### Cut a release

Set the workspace version and internal dependency requirements in `Cargo.toml` and the version in `packages/widget/package.json`. Refresh and commit `Cargo.lock` with the version changes. From the reviewed commit, push the matching tag (for example, `v0.1.0`). The registry workflow checks that tag against every public package before either upload job starts. It builds the Rust archives, tests the widget and loads both exports from an installation of the npm tarball. Pull requests and release tags both run the Rust workspace tests on the release runner.

Cargo uploads dependencies before their consumers. npm publishes the tested tarball with provenance and uses `latest` for stable releases and `next` for prereleases such as `v0.2.0-rc.1`. If an upload fails, rerun the failed job on the same tag. Each registry job checks existing versions against the tested archives and skips matching uploads. A checksum conflict requires investigation before continuing.

If a failure requires a workflow fix after the release tag is public, merge the fix and push a tag named `registry-retry/vX.Y.Z` at the fixed commit. Permit that exact retry tag in both registry environments. The workflow fetches the original `vX.Y.Z` tag, pins the upload jobs to its commit, and checks that the workflow revision contains the same widget sources for npm provenance. Desktop and container distribution continues to use the original release tag.

### Switch to trusted publishing

After the first release, add a GitHub Actions trusted publisher in the settings of **each crate** and the **npm widget**. Use owner `zeroae`, repository `countersign`, workflow filename `publish.yml`, and the environment below.

| Registry | GitHub environment | Publisher permissions |
| --- | --- | --- |
| crates.io | `crates-io` | Configure the publisher for each of the five crates. |
| npm | `npm` | Allow direct `npm publish` for `@zeroae/countersign-widget`. |

Delete the bootstrap secrets from GitHub and revoke both temporary tokens at their registries. Subsequent tags authenticate with the GitHub job's short-lived OIDC identity. Set up the npm publisher within two days of its first OIDC release, or recreate the configuration if it expires. [crates.io trusted publishing](https://crates.io/docs/trusted-publishing) · [npm trusted publishing](https://docs.npmjs.com/trusted-publishers/)
