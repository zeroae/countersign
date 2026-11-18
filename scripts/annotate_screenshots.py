#!/usr/bin/env python3
"""Draw callouts on the handbook screenshots.

scripts/capture_screenshots.mjs writes the raw captures to
docs/assets/screenshots/raw/ together with raw/boxes.json, the CSS-pixel
bounding box of every element a callout highlights. This script never edits
the raw captures. It writes the annotated copies the pages embed to
docs/assets/screenshots/, including a -dark copy wherever a dark capture
exists. Boxes follow the elements, so recapturing needs no coordinate edits.

    pnpm screenshots                                   # capture, then annotate
    uv run --with pillow scripts/annotate_screenshots.py   # annotate only
"""

from __future__ import annotations

import json
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
SHOTS = ROOT / "docs" / "assets" / "screenshots"
RAW = SHOTS / "raw"
OVERSAMPLE = 3  # draw oversampled, then shrink, for smooth edges
ACCENT = (217, 72, 15, 255)
WHITE = (255, 255, 255, 255)
FONT_FILES = ("DejaVuSans-Bold.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", "Verdana Bold.ttf")
# Sizes in CSS pixels; the capture's device scale factor multiplies them.
OUTSET, LINE, RADIUS, FONT, GAP = 4, 3, 5, 12, 6

# output name -> (raw source, [(box key from boxes.json, label, placement[, anchor key])])
# Placement puts the label to the "right" or "left" of the box, "below-end" or
# "above-end" (under or over it, flush with its right edge), or "inside-end"
# (inside its top-right corner). With an anchor key the label is placed
# against that box instead of the highlighted one.
CALLOUTS: dict[str, tuple[str, list[tuple[str, ...]]]] = {
    "approval-unselected.png": ("approval-unselected.png", [
        ("identities", "Same name: compare the highlighted fingerprints", "inside-end"),
        ("actions", "Fixed labels, order and size", "above-end"),
    ]),
    "approval-selected.png": ("approval-selected.png", [
        ("selected", "Selected certificate", "inside-end"),
        ("expiry", "Approval ends here", "inside-end"),
    ]),
    "approval-branding.png": ("approval-selected.png", [
        ("header", "Branding + verified origin", "right"),
        ("facts", "Request facts: fixed rows and order", "inside-end"),
        ("plate", "Fixed Countersign mark", "left"),
    ]),
    "scope-wildcard.png": ("scope-wildcard.png", [
        ("scope", "Exact host vs. what approval covers", "above-end"),
    ]),
    "branding-alternate.png": ("branding-alternate.png", [
        ("header", "Branding + verified origin", "right"),
        ("approve", "Clamped accent colour", "above-end"),
    ]),
    "branding-none.png": ("branding-none.png", [
        ("brand", "No manifest", "right"),
    ]),
    "queue-switch.png": ("queue-switch.png", [
        ("banner", "Fixed banner", "inside-end"),
        ("approve", "Locked for a moment", "above-end"),
    ]),
    "pairing-browser.png": ("pairing-browser.png", [
        ("code", "Code from the Companion", "inside-end"),
    ]),
    "pairing-companion.png": ("pairing-companion.png", [
        ("facts", "Check origin and account", "inside-end"),
        ("code", "Same code as the browser", "inside-end"),
    ]),
    "integrators-list.png": ("integrators-list.png", []),
    "integrator-detail.png": ("integrator-detail.png", [
        ("notice", "Security notice", "inside-end"),
        ("self", "Known from this pairing", "right"),
    ]),
    "branding-review.png": ("branding-review.png", [
        ("review", "Old and new branding", "above-end"),
        ("buttons", "Accept or keep", "right"),
    ]),
    "dialog-remove.png": ("dialog-remove.png", []),
    "widget.png": ("widget.png", [
        ("page", "Integrator page", "below-end"),
        ("widget", "Countersign widget", "below-end"),
    ]),
    "access-active.png": ("access-active.png", [
        ("progress", "Status from the Broker", "above-end"),
    ]),
    "access-ended.png": ("access-ended.png", [
        ("again", "Starts a fresh approval", "right"),
    ]),
    "job-result.png": ("job-result.png", [
        ("match", "Same SHA-256 as the approval", "right"),
    ]),
}


def font(size: int) -> ImageFont.FreeTypeFont:
    for name in FONT_FILES:
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default(size)


def annotate(src: Path, meta: dict, callouts) -> Image.Image:
    base = Image.open(src).convert("RGBA")
    k = meta["scale"] * OVERSAMPLE  # CSS pixels -> overlay pixels
    width, height = base.width * OVERSAMPLE, base.height * OVERSAMPLE
    overlay = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)
    label_font = font(round(FONT * k))
    def box(key: str) -> tuple[float, float, float, float]:
        x0, y0, x1, y1 = (v * k for v in meta["boxes"][key])
        return (max(x0 - OUTSET * k, LINE * k / 2), max(y0 - OUTSET * k, LINE * k / 2),
                min(x1 + OUTSET * k, width - LINE * k / 2), min(y1 + OUTSET * k, height - LINE * k / 2))

    for key, label, placement, *anchor in callouts:
        x0, y0, x1, y1 = box(key)
        draw.rounded_rectangle([x0, y0, x1, y1], radius=RADIUS * k, outline=ACCENT, width=round(LINE * k))
        if anchor:
            x0, y0, x1, y1 = box(anchor[0])
        left, top, right, bottom = draw.textbbox((0, 0), label, font=label_font)
        pad_x, pad_y = 6 * k, 4 * k
        w, h = right - left + 2 * pad_x, bottom - top + 2 * pad_y
        if placement == "right":
            bx, by = x1 + GAP * k, (y0 + y1 - h) / 2
        elif placement == "left":
            bx, by = x0 - GAP * k - w, (y0 + y1 - h) / 2
        elif placement == "below-end":
            bx, by = x1 - w, y1 + GAP * k
        elif placement == "above-end":
            bx, by = x1 - w, y0 - GAP * k - h
        elif placement == "inside-end":
            bx, by = x1 - w - GAP * k, y0 + GAP * k
        else:
            raise ValueError(f"unknown placement {placement!r}")
        bx = min(max(bx, 2 * k), width - w - 2 * k)
        by = min(max(by, 2 * k), height - h - 2 * k)
        draw.rounded_rectangle([bx, by, bx + w, by + h], radius=4 * k, fill=ACCENT)
        draw.text((bx + pad_x - left, by + pad_y - top), label, font=label_font, fill=WHITE)
    overlay = overlay.resize(base.size, Image.LANCZOS)
    return Image.alpha_composite(base, overlay).convert("RGB")


def main() -> None:
    boxes = json.loads((RAW / "boxes.json").read_text())
    for out, (raw, callouts) in CALLOUTS.items():
        variants = [(raw, out)]
        dark = raw.replace(".png", "-dark.png")
        if dark in boxes:
            variants.append((dark, out.replace(".png", "-dark.png")))
        for source, target in variants:
            annotate(RAW / source, boxes[source], callouts).save(SHOTS / target, optimize=True)
            print(f"{source} -> {target}")


if __name__ == "__main__":
    main()
