"""Publish the tested npm archives produced by the desktop build matrix."""
import json
import os
from pathlib import Path
import tarfile

from registry_release import publish_npm_archive

version = json.loads(Path("packages/companion/package.json").read_text())["version"]
if os.environ["GITHUB_REF_NAME"] != f"v{version}":
    raise SystemExit("Release tag must match the desktop version")
launcher = "@zeroae/countersign"
names = [f"{launcher}-{system}-{arch}" for system in ["linux", "darwin", "win32"]
         for arch in ["x64", "arm64"]] + [launcher]
archives = {}
for path in Path("archives").glob("*.tgz"):
    with tarfile.open(path) as package:
        stream = package.extractfile("package/package.json")
        if stream is None:
            raise SystemExit(f"Missing npm manifest in {path}")
        manifest = json.load(stream)
    name = manifest["name"]
    if manifest["version"] != version or name in archives:
        raise SystemExit(f"Unexpected version or duplicate package in {path}")
    archives[name] = path
if set(archives) != set(names):
    raise SystemExit("Expected six platform archives and one launcher archive")
for name in names:
    publish_npm_archive(archives[name], version, name)
