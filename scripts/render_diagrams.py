#!/usr/bin/env python3
"""Render the handbook diagrams in light and dark variants from one palette.

Every colour comes from docs/assets/diagrams/palette.json.

* Hand-drawn diagrams (``*.svg`` with a ``palette:start``/``palette:end`` style
  block) are the light source. Outside that block they may use colours only
  through ``var(--token)``. This script rewrites the block from the tokens and
  writes ``<name>-dark.svg`` beside them.
* Mermaid sequence diagrams (``*.mmd``) and their ``theme.json`` name colours as
  ``{token}``, for example ``rect {band-request}`` or ``"actorBkg":
  "{actor-fill}"``. The script resolves each reference once per mode and exports
  ``<name>.svg`` and ``<name>-dark.svg``.

Any other colour (hex, ``rgb()``/``hsl()``, a named colour) stops the script
with the file and value, so a diagram can't silently keep a light colour in
dark mode.

Run from the checkout root:

    python3 scripts/render_diagrams.py            # everything
    python3 scripts/render_diagrams.py --hand     # hand-drawn SVGs only
    python3 scripts/render_diagrams.py --mermaid  # Mermaid diagrams only

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
BLOCK = re.compile(r"/\* palette:start \*/.*?/\* palette:end \*/", re.S)
TOKEN = re.compile(r"\{([a-z][a-z0-9-]*)\}")
VIEWBOX = re.compile(r'viewBox="([-\d.]+) ([-\d.]+) ([\d.]+) ([\d.]+)"')

# Colour literals that must not appear outside the palette.
LITERAL = re.compile(r"#[0-9a-fA-F]{3,8}\b|\b(?:rgba?|hsla?|hwb|lab|lch|oklab|oklch|color)\s*\(", re.I)
# Colour-bearing properties, as SVG attributes (fill="…") or CSS (fill: …).
PAINT = re.compile(
    r"""(?<![\w-])(fill|stroke|stop-color|flood-color|lighting-color|color|background(?:-color)?)"""
    r"""\s*(?:=\s*["']|:\s*)(\{[a-z][a-z0-9-]*\}|[^;"'}]+)""",
    re.I,
)
# Values a paint property may hold without naming a colour.
NEUTRAL = {"none", "transparent", "currentcolor", "inherit", "context-fill", "context-stroke"}


def load_palette() -> tuple[str, dict[str, dict[str, str]]]:
    data = json.loads((DIAGRAMS / "palette.json").read_text())
    tokens = {name: {m: v.lower() for m, v in modes.items()} for name, modes in data["tokens"].items()}
    for name, modes in tokens.items():
        for mode in ("light", "dark"):
            if not re.fullmatch(r"#[0-9a-f]{6}", modes.get(mode, "")):
                sys.exit(f"palette.json: token {name!r} needs a six-digit hex {mode} value")
    return data["font"], tokens


def stray_colours(text: str, allowed_value) -> list[str]:
    """Return every colour in `text` that does not go through the palette."""
    found = [m.group(0) for m in LITERAL.finditer(text)]
    for prop, value in PAINT.findall(text):
        value = value.strip()
        if value.lower() not in NEUTRAL and not allowed_value(value):
            found.append(f"{prop}: {value}")
    return found


def require_palette(text: str, where: str, allowed_value) -> None:
    stray = stray_colours(text, allowed_value)
    if stray:
        sys.exit(f"{where}: colours must come from palette.json, found: {', '.join(sorted(set(stray)))}")


def palette_block(font: str, tokens: dict, mode: str) -> str:
    props = ";".join(f"--{name}:{t[mode]}" for name, t in tokens.items())
    return f"/* palette:start */ svg{{{props};--font:{font}}} /* palette:end */"


def render_hand(font: str, tokens: dict) -> None:
    def via_var(value: str) -> bool:
        return value.startswith(("var(--", "url(#"))

    for src in sorted(DIAGRAMS.glob("*.svg")):
        text = src.read_text()
        if src.stem.endswith("-dark") or "palette:start" not in text:
            continue
        require_palette(BLOCK.sub("", text), src.name, via_var)
        # A function, not a template string, so palette values are inserted literally.
        light = BLOCK.sub(lambda _: palette_block(font, tokens, "light"), text)
        dark = BLOCK.sub(lambda _: palette_block(font, tokens, "dark"), text)
        src.write_text(light)
        src.with_name(f"{src.stem}-dark.svg").write_text(dark)
        print(f"hand     {src.name} -> {src.stem}-dark.svg")


def resolve(text: str, tokens: dict, mode: str, where: str, rgb: bool = False) -> str:
    """Replace each {token} with its colour for `mode`."""

    def colour(m: re.Match) -> str:
        name = m.group(1)
        if name not in tokens:
            sys.exit(f"{where}: unknown palette token {{{name}}}")
        value = tokens[name][mode]
        if rgb:  # Mermaid's `rect` statement takes rgb(), not hex.
            return "rgb(%d,%d,%d)" % tuple(int(value[i : i + 2], 16) for i in (1, 3, 5))
        return value

    return TOKEN.sub(colour, text)


def is_token(value: str) -> bool:
    return TOKEN.fullmatch(value) is not None


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


def mermaid_theme(font: str, tokens: dict, mode: str) -> dict:
    path = DIAGRAMS / "theme.json"
    raw = path.read_text()
    require_palette(raw, path.name, is_token)
    theme = json.loads(raw)
    for key, value in theme["themeVariables"].items():
        if key not in ("fontFamily", "fontSize") and not is_token(str(value)):
            sys.exit(f"{path.name}: themeVariables.{key} must name a palette token, not {value!r}")
    theme = json.loads(resolve(raw, tokens, mode, path.name))
    theme["themeVariables"]["fontFamily"] = font
    # Mermaid measures text with the top-level font, which overrides per-diagram
    # settings, so it must match the drawn font or labels overflow their boxes.
    theme["fontFamily"] = font
    return theme


def render_mermaid(font: str, tokens: dict) -> None:
    themes = {mode: mermaid_theme(font, tokens, mode) for mode in ("light", "dark")}
    puppeteer = None
    exe = os.environ.get("PUPPETEER_EXECUTABLE_PATH")
    with tempfile.TemporaryDirectory() as tmp:
        if exe:
            puppeteer = Path(tmp) / "puppeteer.json"
            puppeteer.write_text(json.dumps({"executablePath": exe, "args": ["--no-sandbox"]}))
        for src in sorted(DIAGRAMS.glob("*.mmd")):
            source = src.read_text()
            require_palette(source, src.name, is_token)
            for statement in re.findall(r"^\s*rect\s+(\S.*?)\s*$", source, re.M):
                if not is_token(statement):
                    sys.exit(f"{src.name}: `rect {statement}` must name a palette token, e.g. rect {{band-request}}")
            for mode, suffix in (("light", ""), ("dark", "-dark")):
                out = src.with_name(f"{src.stem}{suffix}.svg")
                mmdc(src.stem, resolve(source, tokens, mode, src.name, rgb=True), themes[mode], out,
                     tokens["bg"][mode], puppeteer)
            print(f"mermaid  {src.name} -> {src.stem}.svg, {src.stem}-dark.svg")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    only = parser.add_mutually_exclusive_group()
    only.add_argument("--hand", action="store_true", help="only hand-drawn SVGs")
    only.add_argument("--mermaid", action="store_true", help="only Mermaid diagrams")
    args = parser.parse_args()
    font, tokens = load_palette()
    if not args.mermaid:
        render_hand(font, tokens)
    if not args.hand:
        render_mermaid(font, tokens)


if __name__ == "__main__":
    main()
