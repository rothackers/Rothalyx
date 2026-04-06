#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
build_dir="${BUILD_DIR:-$repo_root/build/release-macos}"
artifact_dir="${ARTIFACT_DIR:-$repo_root/artifacts/macos}"

cmake_args=(
    -S "$repo_root"
    -B "$build_dir"
    -G Ninja
    -DCMAKE_BUILD_TYPE=Release
    -DBUILD_TESTING=OFF
    -DZARA_BUILD_CLI=ON
    -DZARA_BUILD_DESKTOP_QT=ON
)

if command -v brew >/dev/null 2>&1; then
    brew_prefix="$(brew --prefix)"
    cmake_args+=("-DCMAKE_PREFIX_PATH=${brew_prefix}${CMAKE_PREFIX_PATH:+;$CMAKE_PREFIX_PATH}")
elif [[ -n "${CMAKE_PREFIX_PATH:-}" ]]; then
    cmake_args+=("-DCMAKE_PREFIX_PATH=${CMAKE_PREFIX_PATH}")
fi

python3 "$repo_root/scripts/release/generate_icons.py" \
    "$repo_root/apps/desktop_qt/resources/zara-re-platform.png" \
    "$repo_root/apps/desktop_qt/resources"

cmake "${cmake_args[@]}"

cmake --build "$build_dir"
rm -rf "$artifact_dir"
mkdir -p "$artifact_dir"

cpack --config "$build_dir/CPackConfig.cmake" -G DragNDrop -B "$artifact_dir"
find "$artifact_dir" -mindepth 1 -maxdepth 1 ! -name '*.dmg' -exec rm -rf {} +
