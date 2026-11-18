#!/usr/bin/env python3
"""Render the handbook diagrams in light and dark variants from one palette.

Every colour comes from docs/assets/diagrams/palette.json.

* Hand-drawn diagrams (``*.svg`` with a ``palette:start``/``palette:end`` style
  block) are the light source. This script rewrites their palette block from
  the tokens and writes ``<name>-dark.svg`` beside them.
* Mermaid sequence diagrams (``*.mmd``) are exported with ``theme.json`` for the
  light variant and a dark theme derived from it by swapping each light token
  for its dark value. ``rect rgb(...)`` bands in the source are swapped too.

Run from the checkout root:

    python3 scripts/render_diagrams.py            # everything
    python3 scripts/render_diagrams.py --hand     # hand-drawn SVGs only

Mermaid export needs Node and a Chromium that Puppeteer can launch. Set
PUPPETEER_EXECUTABLE_PATH to use an existing browser.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIAGRAMS = ROOT / "docs" / "assets" / "diagrams"
MERMAID_CLI = "@mermaid-js/mermaid-cli@11.12.0"
HEX = re.compile(r"#[0-9a-fA-F]{6}\b")
BLOCK = re.compile(r"/\* palette:start \*/.*?/\* palette:end \*/", re.S)
RGB = re.compile(r"rgb\((\d+),\s*(\d+),\s*(\d+)\)")
VIEWBOX = re.compile(r'viewBox="([-\d.]+) ([-\d.]+) ([\d.]+) ([\d.]+)"')


def load_palette() -> tuple[str, dict[str, dict[str, str]]]:
    data = json.loads((DIAGRAMS / "palette.json").read_text())
    tokens = {name: {m: v.lower() for m, v in modes.items()} for name, modes in data["tokens"].items()}
    lights = [t["light"] for t in tokens.values()]
    if len(set(lights)) != len(lights):
        sys.exit("palette.json: light values must be unique so dark variants can be derived")
    return data["font"], tokens


def palette_block(font: str, tokens: dict, mode: str) -> str:
    props = ";".join(f"--{name}:{t[mode]}" for name, t in tokens.items())
    return f"/* palette:start */ svg{{{props};--font:{font}}} /* palette:end */"


def check_hex(text: str, allowed: set[str], where: str) -> None:
    stray = {h.lower() for h in HEX.findall(text)} - allowed
    if stray:
        sys.exit(f"{where}: colours outside palette.json: {', '.join(sorted(stray))}")


def render_hand(font: str, tokens: dict) -> None:
    for src in sorted(DIAGRAMS.glob("*.svg")):
        text = src.read_text()
        if src.stem.endswith("-dark") or "palette:start" not in text:
            continue
        outside = BLOCK.sub("", text)
        check_hex(outside, set(), src.name)  # all colours must go through var(--token)
        light = BLOCK.sub(palette_block(font, tokens, "light"), text)
        dark = BLOCK.sub(palette_block(font, tokens, "dark"), text)
        src.write_text(light)
        src.with_name(f"{src.stem}-dark.svg").write_text(dark)
        print(f"hand     {src.name} -> {src.stem}-dark.svg")


def to_dark(text: str, tokens: dict) -> str:
    swap = {t["light"]: t["dark"] for t in tokens.values()}

    def hex_sub(m: re.Match) -> str:
        return swap[m.group(0).lower()]

    def rgb_sub(m: re.Match) -> str:
        light = "#%02x%02x%02x" % tuple(int(v) for v in m.groups())
        dark = swap.get(light)
        if dark is None:
            sys.exit(f"rgb({', '.join(m.groups())}) is not a palette.json light token")
        return "rgb(%d,%d,%d)" % tuple(int(dark[i : i + 2], 16) for i in (1, 3, 5))

    return RGB.sub(rgb_sub, HEX.sub(hex_sub, text))


def fix_size(svg: str) -> str:
    """Give Mermaid output an intrinsic size so it is never stretched past 1:1."""
    m = VIEWBOX.search(svg)
    if not m:
        return svg
    width, height = (round(float(v)) for v in m.group(3, 4))
    head, rest = svg.split(">", 1)
    head = re.sub(r'\s(?:width|height)="[^"]*"', "", head)
    head = re.sub(r"max-width:\s*[\d.]+px;?\s*", "", head)
    head += f' width="{width}" height="{height}"'
    return head + ">" + rest


def mmdc(name: str, source: str, theme: dict, out: Path, background: str, puppeteer: Path | None) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = Path(tmp) / "theme.json"
        cfg.write_text(json.dumps(theme))
        mmd = Path(tmp) / f"{name}.mmd"
        mmd.write_text(source)
        cmd = ["npx", "--yes", f"--package={MERMAID_CLI}", "mmdc", "-i", str(mmd), "-o", str(out),
               "-c", str(cfg), "-I", name, "-b", background, "-q"]
        if puppeteer:
            cmd += ["-p", str(puppeteer)]
        subprocess.run(cmd, check=True)
    out.write_text(fix_size(out.read_text()))


def render_mermaid(font: str, tokens: dict) -> None:
    theme_text = (DIAGRAMS / "theme.json").read_text()
    allowed = {t["light"] for t in tokens.values()}
    check_hex(theme_text, allowed, "theme.json")
    light = json.loads(theme_text)
    light["themeVariables"]["fontFamily"] = font
    # Mermaid measures text with the top-level font, which overrides per-diagram
    # settings, so it must match the drawn font or labels overflow their boxes.
    light["fontFamily"] = font
    dark = json.loads(to_dark(json.dumps(light), tokens))
    bg = tokens["bg"]

    puppeteer = None
    exe = os.environ.get("PUPPETEER_EXECUTABLE_PATH")
    with tempfile.TemporaryDirectory() as tmp:
        if exe:
            puppeteer = Path(tmp) / "puppeteer.json"
            puppeteer.write_text(json.dumps({"executablePath": exe, "args": ["--no-sandbox"]}))
        for src in sorted(DIAGRAMS.glob("*.mmd")):
            source = src.read_text()
            mmdc(src.stem, source, light, src.with_suffix(".svg"), bg["light"], puppeteer)
            mmdc(src.stem, to_dark(source, tokens), dark, src.with_name(f"{src.stem}-dark.svg"), bg["dark"], puppeteer)
            print(f"mermaid  {src.name} -> {src.stem}.svg, {src.stem}-dark.svg")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--hand", action="store_true", help="only hand-drawn SVGs")
    parser.add_argument("--mermaid", action="store_true", help="only Mermaid diagrams")
    args = parser.parse_args()
    font, tokens = load_palette()
    if not args.mermaid:
        render_hand(font, tokens)
    if not args.hand:
        render_mermaid(font, tokens)


if __name__ == "__main__":
    main()
