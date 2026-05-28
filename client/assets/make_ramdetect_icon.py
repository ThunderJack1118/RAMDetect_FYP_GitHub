from __future__ import annotations

"""
Create a properly cropped RAMDetect .ico from ramdetect.png.

This fixes tiny Windows titlebar/Explorer icons caused by the original PNG
having dark/transparent padding around the logo mark.
"""

import sys
from pathlib import Path

try:
    from PIL import Image
except Exception as exc:
    print(f"[RAMDetect] Pillow is required for icon generation: {exc}", file=sys.stderr)
    sys.exit(2)


def find_project_root() -> Path:
    here = Path.cwd().resolve()
    for p in [here, *here.parents]:
        if (p / "main.py").is_file() and (p / "ramdetect").is_dir():
            return p
    return here


def find_logo(root: Path) -> Path:
    candidates = [
        root / "ramdetect" / "ui" / "resources" / "photo" / "ramdetect.png",
        root / "ui" / "resources" / "photo" / "ramdetect.png",
        root / "assets" / "ramdetect.png",
    ]
    for p in candidates:
        if p.is_file():
            return p
    raise FileNotFoundError("Could not find ramdetect.png in ramdetect/ui/resources/photo or assets.")


def crop_dark_padding(img: Image.Image) -> Image.Image:
    rgba = img.convert("RGBA")
    pix = rgba.load()
    w, h = rgba.size

    min_x, min_y, max_x, max_y = w, h, -1, -1
    for y in range(h):
        for x in range(w):
            r, g, b, a = pix[x, y]
            # Logo mark is non-dark/non-transparent. Keep future coloured logos too.
            if a > 10 and max(r, g, b) > 28:
                min_x = min(min_x, x)
                min_y = min(min_y, y)
                max_x = max(max_x, x)
                max_y = max(max_y, y)

    if max_x < min_x or max_y < min_y:
        return rgba

    cw = max_x - min_x + 1
    ch = max_y - min_y + 1
    pad = max(8, int(max(cw, ch) * 0.10))
    min_x = max(0, min_x - pad)
    min_y = max(0, min_y - pad)
    max_x = min(w - 1, max_x + pad)
    max_y = min(h - 1, max_y + pad)
    return rgba.crop((min_x, min_y, max_x + 1, max_y + 1))


def square_canvas(img: Image.Image, margin_ratio: float = 0.08) -> Image.Image:
    img = img.convert("RGBA")
    side = max(img.size)
    canvas = Image.new("RGBA", (side, side), (0, 0, 0, 0))
    canvas.alpha_composite(img, ((side - img.width) // 2, (side - img.height) // 2))

    # Add a small transparent margin so the mark does not touch icon edges.
    out_side = int(side / (1.0 - margin_ratio * 2))
    out = Image.new("RGBA", (out_side, out_side), (0, 0, 0, 0))
    out.alpha_composite(canvas, ((out_side - side) // 2, (out_side - side) // 2))
    return out


def main() -> int:
    root = find_project_root()
    logo = find_logo(root)
    assets = root / "assets"
    assets.mkdir(parents=True, exist_ok=True)
    out = assets / "ramdetect.ico"

    img = Image.open(logo)
    img = crop_dark_padding(img)
    img = square_canvas(img)

    sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    img.save(out, format="ICO", sizes=sizes)

    print(f"[RAMDetect] Source logo : {logo}")
    print(f"[RAMDetect] Wrote icon  : {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
