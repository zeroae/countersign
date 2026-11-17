#!/usr/bin/env bash
set -euo pipefail
export RUSTFLAGS="${RUSTFLAGS:-} -L native=$PREFIX/lib"
cargo build --locked --release -p countersign-native
pnpm install --frozen-lockfile
node scripts/native-package.mjs
pnpm --filter @countersign/companion exec electron-builder --dir --publish never
install -d "$PREFIX/lib" "$PREFIX/bin" "$PREFIX/share/applications"
appdir=$(find packages/companion/dist -mindepth 1 -maxdepth 1 -type d -name '*unpacked' -print -quit)
test -n "$appdir"
cp -a "$appdir" "$PREFIX/lib/countersign-companion"
ln -s ../lib/countersign-companion/countersign-companion "$PREFIX/bin/countersign-companion"
cat >"$PREFIX/share/applications/io.zeroae.countersign.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=Countersign
Exec=countersign-companion %U
Terminal=false
Categories=Utility;
MimeType=x-scheme-handler/countersign;
DESKTOP
