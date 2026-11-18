#!/usr/bin/env python3
"""Draw callouts on the handbook screenshots.

Raw captures live in docs/assets/screenshots/raw/ and are never edited. This
script writes the annotated copies the pages embed to docs/assets/screenshots/.
After recapturing a screen, check that the boxes below still frame the right
rows and adjust them before regenerating.

    uv run --with pillow scripts/annotate_screenshots.py
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
SHOTS = ROOT / "docs" / "assets" / "screenshots"
RAW = SHOTS / "raw"
SCALE = 3  # draw oversampled, then shrink, for smooth edges at 1x
ACCENT = (217, 72, 15, 255)
WHITE = (255, 255, 255, 255)
FONT_FILES = ("DejaVuSans-Bold.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", "Verdana Bold.ttf")

# output name -> (raw source, [(box (x0, y0, x1, y1), label, label anchor (x, y))])
# Coordinates are in raw-image pixels. The label's top-left corner sits at the anchor.
CALLOUTS: dict[str, tuple[str, list[tuple[tuple[int, int, int, int], str, tuple[int, int]]]]] = {
    "approval-unselected.png": ("approval-unselected.png", [
        ((25, 283, 685, 451), "Same name: compare issuer, expiry, SHA-256", (300, 286)),
        ((15, 583, 112, 624), "Disabled until you choose", (195, 594)),
    ]),
    "approval-selected.png": ("approval-selected.png", [
        ((25, 372, 685, 451), "Selected certificate", (480, 376)),
        ((15, 530, 304, 554), "Approval ends here", (316, 530)),
    ]),
    "scope-wildcard.png": ("scope-wildcard.png", [
        ((14, 188, 410, 238), "Exact host vs. what approval covers", (420, 200)),
    ]),
    "approval-branding.png": ("approval-selected.png", [
        ((16, 14, 692, 62), "Integrator branding", (518, 69)),
    ]),
    "branding-alternate.png": ("branding-alternate.png", [
        ((16, 14, 692, 84), "Integrator branding", (518, 91)),
    ]),
    "pairing-browser.png": ("pairing-browser.png", [
        ((189, 199, 382, 224), "Code from the Companion", (245, 227)),
    ]),
    "pairing-companion.png": ("pairing-companion.png", [
        ((24, 204, 536, 234), "Check origin, account and code", (546, 210)),
    ]),
    "widget.png": ("widget.png", [
        ((5, 197, 356, 264), "Countersign widget", (366, 202)),
    ]),
}


def font(size: int) -> ImageFont.FreeTypeFont:
    for name in FONT_FILES:
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default(size)


def annotate(src: Path, callouts) -> Image.Image:
    base = Image.open(src).convert("RGBA")
    overlay = Image.new("RGBA", (base.width * SCALE, base.height * SCALE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)
    label_font = font(12 * SCALE)
    for (x0, y0, x1, y1), label, (lx, ly) in callouts:
        draw.rounded_rectangle([x0 * SCALE, y0 * SCALE, x1 * SCALE, y1 * SCALE],
                               radius=5 * SCALE, outline=ACCENT, width=3 * SCALE)
        left, top, right, bottom = draw.textbbox((0, 0), label, font=label_font)
        pad_x, pad_y = 6 * SCALE, 4 * SCALE
        w, h = right - left + 2 * pad_x, bottom - top + 2 * pad_y
        bx = min(lx * SCALE, overlay.width - w - 2 * SCALE)
        by = ly * SCALE
        draw.rounded_rectangle([bx, by, bx + w, by + h], radius=4 * SCALE, fill=ACCENT)
        draw.text((bx + pad_x - left, by + pad_y - top), label, font=label_font, fill=WHITE)
    overlay = overlay.resize(base.size, Image.LANCZOS)
    return Image.alpha_composite(base, overlay).convert("RGB")


def main() -> None:
    for out, (raw, callouts) in CALLOUTS.items():
        annotate(RAW / raw, callouts).save(SHOTS / out, optimize=True)
        print(f"{raw} -> {out}")


if __name__ == "__main__":
    main()
