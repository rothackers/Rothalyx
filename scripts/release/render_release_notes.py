#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path


def detect_platform_label(filename: str) -> str:
    lower = filename.lower()
    if lower.endswith(".exe") or lower.endswith(".msi"):
        return "Windows"
    if lower.endswith(".dmg"):
        return "macOS"
    if lower.endswith(".appimage"):
        return "Linux"
    if lower.endswith(".deb"):
        return "Debian / Ubuntu"
    if ".pkg.tar." in lower:
        return "Arch Linux"
    if lower == "sha256sums.txt":
        return "Checksums"
    return "Artifact"


def detect_package_label(filename: str) -> str:
    lower = filename.lower()
    if lower.endswith(".exe"):
        return "NSIS installer"
    if lower.endswith(".msi"):
        return "MSI installer"
    if lower.endswith(".dmg"):
        return "DMG"
    if lower.endswith(".appimage"):
        return "AppImage"
    if lower.endswith(".deb"):
        return "DEB package"
    if ".pkg.tar." in lower:
        return "Pacman package"
    if lower == "sha256sums.txt":
        return "SHA256 checksums"
    return "Release artifact"


def ordered_assets(assets_dir: Path) -> list[Path]:
    files = [path for path in assets_dir.iterdir() if path.is_file()]
    order = {
        "windows": 0,
        "macos": 1,
        "linux-appimage": 2,
        "linux-deb": 3,
        "arch": 4,
        "checksums": 5,
    }

    def key(path: Path) -> tuple[int, str]:
        lower = path.name.lower()
        if lower.endswith(".exe") or lower.endswith(".msi"):
            return (order["windows"], lower)
        if lower.endswith(".dmg"):
            return (order["macos"], lower)
        if lower.endswith(".appimage"):
            return (order["linux-appimage"], lower)
        if lower.endswith(".deb"):
            return (order["linux-deb"], lower)
        if ".pkg.tar." in lower:
            return (order["arch"], lower)
        if lower == "sha256sums.txt":
            return (order["checksums"], lower)
        return (99, lower)

    return sorted(files, key=key)


def build_download_table(assets_dir: Path, version: str) -> str:
    base_url = f"https://github.com/{{owner}}/{{repo}}/releases/download/{version}"
    rows = [
        "| Platform | Package | File |",
        "| --- | --- | --- |",
    ]
    for asset in ordered_assets(assets_dir):
        rows.append(
            f"| {detect_platform_label(asset.name)} | {detect_package_label(asset.name)} | "
            f"[`{asset.name}`]({base_url}/{asset.name}) |"
        )
    return "\n".join(rows)


def load_release_body(version: str, notes_dir: Path) -> str:
    notes_path = notes_dir / f"{version}.md"
    if notes_path.exists():
        return notes_path.read_text(encoding="utf-8").rstrip()

    return (
        f"# What's New in {version}\n\n"
        "This release ships the current Zara desktop application, core analysis stack, "
        "SDK surface, and cross-platform packaging artifacts.\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Render GitHub release notes for a tagged Zara release.")
    parser.add_argument("--version", required=True, help="Version or tag name, for example v1.0.0")
    parser.add_argument("--repository", required=True, help="GitHub repository in owner/name form")
    parser.add_argument("--assets-dir", required=True, help="Directory that contains packaged release assets")
    parser.add_argument("--notes-dir", default=".github/release-notes", help="Directory with versioned release note bodies")
    parser.add_argument("--output", required=True, help="Output markdown file")
    args = parser.parse_args()

    assets_dir = Path(args.assets_dir)
    notes_dir = Path(args.notes_dir)
    output_path = Path(args.output)

    body = load_release_body(args.version, notes_dir).rstrip()
    table = build_download_table(assets_dir, args.version).replace("{owner}/{repo}", args.repository)

    rendered = (
        body
        + "\n\n## Downloads\n\n"
        + table
        + "\n"
    )
    output_path.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
