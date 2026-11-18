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

The recipe installs Electron, the launcher and the matching native addon. A future conda-forge submission needs an owner-selected license and a versioned release source with its checksum. [Recipe and package tests](https://github.com/zeroae/countersign/blob/fbb5aa7c951f8b70a238f3351140aa44a6184adf/recipe/recipe.yaml)

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

Version tags matching `v*` trigger desktop builds, native prebuilds, GitHub release assets with `SHA256SUMS`, and the two GHCR images tagged with the release name. The image names are `ghcr.io/zeroae/countersign-gateway` and `ghcr.io/zeroae/countersign-broker`. Windows signing and macOS signing and notarization require the repository variable `COUNTERSIGN_SIGN_RELEASES=true` and the corresponding release secrets. A signed release still needs qualification on its intended operating systems. The widget is consumed from the workspace and the conda channel above is local. [Release workflow and required secrets](https://github.com/zeroae/countersign/blob/fbb5aa7c951f8b70a238f3351140aa44a6184adf/.github/workflows/distribution.yml)
