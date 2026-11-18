"""Add one release to mike's local gh-pages branch and export the Pages artifact."""
import argparse
import html
import json
import os
from pathlib import Path
import subprocess

from packaging.version import Version


def run(*command):
    subprocess.run(command, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", help="Release version without the leading v")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    current = Version(args.version)
    published = json.loads(subprocess.check_output(["mike", "list", "--json"]))
    stable = [Version(item["version"]) for item in published
              if not Version(item["version"]).is_prerelease]
    aliases = []
    if not current.is_prerelease:
        series = current.release[:2]
        if all(current >= old for old in stable if old.release[:2] == series):
            aliases.append(f"{current.major}.{current.minor}")
        if all(current >= old for old in stable):
            aliases.append("latest")
    run("mike", "deploy", "--update-aliases", "--alias-type", "redirect", args.version, *aliases)
    run("mike", "set-default", "latest" if stable or "latest" in aliases else args.version)

    args.output.mkdir(parents=True, exist_ok=False)
    archive = args.output / "handbook.tar"
    run("git", "archive", "gh-pages", "-o", str(archive))
    run("tar", "-xf", str(archive), "-C", str(args.output))
    archive.unlink()
    # Preserve unversioned deep links from the repository and registry READMEs.
    for page in (args.output / "latest").rglob("index.html"):
        relative = page.relative_to(args.output / "latest")
        if relative == Path("index.html"):
            continue
        redirect = args.output / relative
        redirect.parent.mkdir(parents=True, exist_ok=True)
        url = os.path.relpath(page.parent, redirect.parent) + "/"
        redirect.write_text(
            '<!doctype html><meta charset="utf-8">'
            f'<script>location.replace({json.dumps(url)}+location.search+location.hash)</script>'
            f'<meta http-equiv="refresh" content="0;url={html.escape(url, quote=True)}">'
            f'<a href="{html.escape(url, quote=True)}">Open the current handbook</a>\n'
        )


if __name__ == "__main__":
    main()
