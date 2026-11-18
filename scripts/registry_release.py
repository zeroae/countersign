"""Release the registry packages from a version tag. Run from the repository root."""

import argparse
import base64
import hashlib
import json
import subprocess
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen


def cargo_packages():
    metadata = subprocess.check_output(
        ["cargo", "metadata", "--format-version=1", "--no-deps", "--locked"]
    )
    return [p for p in json.loads(metadata)["packages"] if p["publish"] == ["crates-io"]]


def registry_version(url):
    request = Request(url, headers={"User-Agent": "Countersign release (github.com/zeroae/countersign)"})
    try:
        with urlopen(request, timeout=30) as response:
            return json.load(response)
    except HTTPError as error:
        if error.code == 404:
            return None
        raise


def verify_tag(tag, version, packages):
    if not packages or any(package["version"] != version for package in packages):
        raise SystemExit("The widget and publishable Cargo packages must have the same version")
    if tag != f"v{version}" or "+" in version:
        raise SystemExit(f"Expected tag v{version} (npm release versions exclude build metadata)")


def publish_crates(directory, version, packages):
    selection = []
    for package in packages:
        name = package["name"]
        archive = directory / f"{name}-{version}.crate"
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        existing = registry_version(f"https://crates.io/api/v1/crates/{name}/{version}")
        if existing is None:
            selection.extend(["--package", name])
        elif existing["version"]["yanked"] or existing["version"]["checksum"] != digest:
            raise SystemExit(f"Published {name}@{version} is yanked or has a different checksum")
        else:
            print(f"Already published {name}@{version}", flush=True)
    if selection:
        # Cargo publishes workspace dependencies first and waits for them to reach the index.
        subprocess.run(["cargo", "publish", "--registry", "crates-io", "--locked",
                        "--no-verify", *selection], check=True)


def publish_widget(directory, version, name):
    archive, = directory.glob("*.tgz")
    checksum = hashlib.sha512(archive.read_bytes()).digest()
    integrity = "sha512-" + base64.b64encode(checksum).decode("ascii")
    registry = "https://registry.npmjs.org"
    existing = registry_version(f"{registry}/{quote(name, safe='')}/{version}")
    if existing is not None:
        if existing["dist"]["integrity"] != integrity:
            raise SystemExit(f"Published {name}@{version} has a different checksum")
        print(f"Already published {name}@{version}", flush=True)
        return
    dist_tag = "next" if "-" in version else "latest"
    subprocess.run(["npm", "publish", str(archive.resolve()), "--ignore-scripts",
                    "--registry", registry, "--access", "public", "--provenance",
                    "--tag", dist_tag], check=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["check", "crates", "widget"])
    parser.add_argument("--tag")
    parser.add_argument("--archives", type=Path)
    args = parser.parse_args()
    widget = json.loads(Path("packages/widget/package.json").read_text())
    version = widget["version"]
    if args.action != "check" and not (args.tag and args.archives):
        parser.error("publishing requires --tag and --archives")
    packages = cargo_packages()
    verify_tag(args.tag if args.tag is not None else f"v{version}", version, packages)
    if args.action == "crates":
        publish_crates(args.archives, version, packages)
    elif args.action == "widget":
        publish_widget(args.archives, version, widget["name"])
