#!/usr/bin/env python3
"""Build the Splunk app icons and logos from the official Aviatrix brand mark.

    python3 tools/brand/build_icons.py

Writes two SVG masters next to this script and the PNGs Splunk loads from each
app's static/ directory (Splunk does not read SVG app icons):

    appIcon.png 36x36, appIcon_2x.png 72x72        square mark, transparent
    appLogo.png 160x40, appLogo_2x.png 320x80      mark + wordmark, transparent

Everything is transparent so the icon sits cleanly on Splunk 10's side
navigation and Splunk 9's app bar in both light and dark themes. The paths are
the official Aviatrix logo (aviatrix-on-black.svg: orange mark #FA6B1E, white
wordmark), unmodified; only placement and padding are set here.

Rendering: ImageMagick's SVG renderer at 8x, then a Lanczos downscale, which
gives clean anti-aliasing at 36 px. Requires `magick` and Pillow.
"""
import io
import os
import re
import subprocess

from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
APPS = ["TA-aviatrix", "aviatrix-security"]
SOURCE = os.path.join(HERE, "aviatrix-logo-on-black.svg")

ORANGE = "#FA6B1E"
MARK_BOX = (-0.5, 8.8, 85.3, 60.0)  # x, y, w, h of the mark in the brand viewBox


def brand_paths():
    svg = open(SOURCE).read()
    return re.findall(r'<path d="([^"]+)" fill="([^"]+)"', svg)


def icon_svg(size=100, pad=0.08):
    """Square icon: the mark centered with `pad` margin on the wider side."""
    mark_d = next(d for d, f in brand_paths() if f.upper() == ORANGE)
    x, y, w, h = MARK_BOX
    scale = size * (1 - 2 * pad) / max(w, h)
    tx = (size - w * scale) / 2 - x * scale
    # Optical centering: the chevron's mass sits low, so lift it slightly.
    ty = (size - h * scale) / 2 - y * scale - size * 0.02
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" width="{size}" height="{size}">'
            f'<title>Aviatrix</title>'
            f'<path transform="translate({tx:.3f} {ty:.3f}) scale({scale:.5f})" d="{mark_d}" fill="{ORANGE}"/></svg>')


def logo_svg(width=320, height=80, pad_x=10, pad_y=14):
    """Mark + wordmark (white letters for Splunk's dark navigation)."""
    paths = brand_paths()
    x0, y0, x1, y1 = -0.5, 8.8, 399.2, 68.8
    scale = min((width - 2 * pad_x) / (x1 - x0), (height - 2 * pad_y) / (y1 - y0))
    tx = pad_x - x0 * scale
    ty = (height - (y1 - y0) * scale) / 2 - y0 * scale
    body = "".join(f'<path d="{d}" fill="{f}"/>' for d, f in paths)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}">'
            f'<title>Aviatrix</title><g transform="translate({tx:.3f} {ty:.3f}) scale({scale:.5f})">{body}</g></svg>')


def render(svg, w, h, oversample=8):
    big = subprocess.run(
        ["magick", "-background", "none", "-density", str(72 * oversample), "svg:-", "png:-"],
        input=svg.encode(), capture_output=True, check=True).stdout
    im = Image.open(io.BytesIO(big)).convert("RGBA")
    return im.resize((w, h), Image.LANCZOS)


def main():
    icon, logo = icon_svg(), logo_svg()
    open(os.path.join(HERE, "aviatrix-app-icon.svg"), "w").write(icon)
    open(os.path.join(HERE, "aviatrix-app-logo.svg"), "w").write(logo)
    outputs = {"appIcon.png": (icon, 36, 36), "appIcon_2x.png": (icon, 72, 72),
               "appLogo.png": (logo, 160, 40), "appLogo_2x.png": (logo, 320, 80)}
    for name, (svg, w, h) in outputs.items():
        im = render(svg, w, h)
        assert im.getpixel((0, 0))[3] == 0, f"{name}: corner is not transparent"
        for app in APPS:
            path = os.path.join(ROOT, app, "static", name)
            im.save(path, optimize=True)
            print("wrote", os.path.relpath(path, ROOT), im.size)


if __name__ == "__main__":
    main()
