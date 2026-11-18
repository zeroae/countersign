"""Pack the launcher and the current runner's desktop installer for npm."""
import filecmp
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[2]
out = root / "npm-archives"
out.mkdir(exist_ok=True)
version = json.loads((root / "packages/companion/package.json").read_text())["version"]
name = "@zeroae/countersign"
npm_path = shutil.which("npm.cmd" if os.name == "nt" else "npm")
if npm_path is None:
    raise SystemExit("npm is required to pack desktop binaries")
npm: str = npm_path
systems = {"linux": "AppImage", "darwin": "pkg", "win32": "exe"}
arch = subprocess.check_output(["node", "-p", "process.arch"], text=True).strip()
if arch not in {"x64", "arm64"}:
    raise RuntimeError(f"Unsupported Node architecture {arch}")
target = f"{name}-{sys.platform}-{arch}"
extension = systems[sys.platform]
installer, = (root / "packages/companion/dist").glob(f"*.{extension}")
common = {"version": version, "license": "MIT", "repository": {"type": "git",
          "url": "git+https://github.com/zeroae/countersign.git"}, "homepage": "https://zeroae.github.io/countersign/companion/"}


def pack(directory, metadata):
    (directory / "package.json").write_text(json.dumps({**common, **metadata}, indent=2) + "\n")
    shutil.copy(root / "LICENSE", directory)
    shutil.copy(root / "distribution/npm/README.md", directory)
    [result] = json.loads(subprocess.check_output(
        [npm, "pack", "--ignore-scripts", "--json", "--pack-destination", str(out)],
        cwd=directory, text=True))
    return out / result["filename"]


with tempfile.TemporaryDirectory() as tmp:
    staging = Path(tmp)
    payload = staging / "payload"
    payload.mkdir()
    binary = payload / installer.name
    shutil.copy2(installer, binary)
    binary.chmod(0o755)
    archive = pack(payload, {"name": target, "os": [sys.platform], "cpu": [arch],
                            "description": f"Countersign desktop binary for {sys.platform} {arch}",
                            "installer": binary.name})
    launcher = staging / "launcher"
    launcher.mkdir()
    script = launcher / "launch.cjs"
    shutil.copy(root / "distribution/npm/launch.cjs", script)
    script.chmod(0o755)
    command = pack(launcher, {"name": name, "description": "Install or launch Countersign on your desktop",
                   "bin": {"countersign": "launch.cjs"}, "optionalDependencies": {
                       f"{name}-{system}-{cpu}": version for system in systems for cpu in ["x64", "arm64"]}})
    consumer = staging / "consumer"
    consumer.mkdir()
    (consumer / "package.json").write_text('{"private": true}\n')
    subprocess.run([npm, "install", "--offline", "--ignore-scripts", "--no-audit",
                    "--no-fund", str(archive), str(command)], cwd=consumer, check=True)
    entry = consumer / "node_modules/@zeroae/countersign/launch.cjs"
    installed = subprocess.check_output(["node", str(entry), "--print-path"], cwd=consumer, text=True).strip()
    if not filecmp.cmp(installed, installer, shallow=False):
        raise RuntimeError("Installed npm payload differs from the desktop artifact")
    if sys.platform == "linux" and not os.access(installed, os.X_OK):
        raise RuntimeError("Installed AppImage lacks execute permission")
    # Publish a single canonical launcher archive from Linux x64.
    if (sys.platform, arch) != ("linux", "x64"):
        command.unlink()
