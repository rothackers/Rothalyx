#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image


ICO_SIZES = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
ICNS_SIZES = [(16, 16), (32, 32), (64, 64), (128, 128), (256, 256), (512, 512), (1024, 1024)]
LINUX_ICON_SIZE = (512, 512)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate Windows/macOS icon assets from a master PNG.")
    parser.add_argument("source", type=Path, help="Source PNG path")
    parser.add_argument("output_dir", type=Path, help="Directory to write icon assets into")
    args = parser.parse_args()

    source = args.source.resolve()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    image = Image.open(source).convert("RGBA")

    linux_icon_path = output_dir / "zara-re-platform-512.png"
    linux_icon = image.resize(LINUX_ICON_SIZE, Image.Resampling.LANCZOS)
    linux_icon.save(linux_icon_path, format="PNG")

    ico_path = output_dir / "zara-re-platform.ico"
    image.save(ico_path, format="ICO", sizes=ICO_SIZES)

    icns_path = output_dir / "zara-re-platform.icns"
    image.save(icns_path, format="ICNS", sizes=ICNS_SIZES)

    print(f"Generated {linux_icon_path}")
    print(f"Generated {ico_path}")
    print(f"Generated {icns_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
