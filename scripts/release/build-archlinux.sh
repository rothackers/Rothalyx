#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_dir="${ARTIFACT_DIR:-$repo_root/artifacts/archlinux}"

python3 "$repo_root/scripts/release/generate_icons.py" \
    "$repo_root/apps/desktop_qt/resources/zara-re-platform.png" \
    "$repo_root/apps/desktop_qt/resources"

rm -rf "$artifact_dir"
mkdir -p "$artifact_dir"
mapfile -t package_paths < <(makepkg --packagelist)
makepkg -s --noconfirm --cleanbuild
cp -v "${package_paths[@]}" "$artifact_dir"/
