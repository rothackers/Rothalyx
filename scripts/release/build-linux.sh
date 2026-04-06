#!/usr/bin/env bash
set -euo pipefail

mode="${1:-all}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
build_dir="${BUILD_DIR:-$repo_root/build/release-linux}"
artifact_dir="${ARTIFACT_DIR:-$repo_root/artifacts/linux}"
install_prefix="${INSTALL_PREFIX:-/usr}"
appdir="$artifact_dir/AppDir"

python3 "$repo_root/scripts/release/generate_icons.py" \
    "$repo_root/apps/desktop_qt/resources/zara-re-platform.png" \
    "$repo_root/apps/desktop_qt/resources"

cmake -S "$repo_root" -B "$build_dir" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$install_prefix" \
    -DBUILD_TESTING=OFF \
    -DZARA_BUILD_CLI=ON \
    -DZARA_BUILD_DESKTOP_QT=ON

cmake --build "$build_dir"
mkdir -p "$artifact_dir"

if [[ "$mode" == "deb" || "$mode" == "all" ]]; then
    rm -rf "$artifact_dir/_CPack_Packages"
    find "$artifact_dir" -maxdepth 1 -type f -name '*.deb' -delete
    cpack --config "$build_dir/CPackConfig.cmake" -G DEB -B "$artifact_dir"
fi

if [[ "$mode" == "appimage" || "$mode" == "all" ]]; then
    : "${LINUXDEPLOY:?LINUXDEPLOY must point to the linuxdeploy AppImage}"
    : "${LINUXDEPLOY_PLUGIN_QT:?LINUXDEPLOY_PLUGIN_QT must point to the linuxdeploy Qt plugin AppImage}"
    : "${APPIMAGETOOL:?APPIMAGETOOL must point to the appimagetool AppImage}"

    rm -rf "$appdir"
    find "$artifact_dir" -maxdepth 1 -type f -name '*.AppImage' -delete
    cmake --install "$build_dir" --prefix "$appdir/usr"
    install -Dm0644 \
        "$repo_root/apps/desktop_qt/resources/zara-re-platform-512.png" \
        "$appdir/usr/share/icons/hicolor/512x512/apps/zara-re-platform.png"

    chmod +x "$LINUXDEPLOY" "$LINUXDEPLOY_PLUGIN_QT" "$APPIMAGETOOL"
    export APPIMAGE_EXTRACT_AND_RUN=1
    export QMAKE="${QMAKE:-qmake6}"
    export VERSION="${VERSION:-${GITHUB_REF_NAME:-1.0.0}}"

    pushd "$artifact_dir" >/dev/null
    "$LINUXDEPLOY" \
        --appdir "$appdir" \
        --desktop-file "$appdir/usr/share/applications/zara-re-platform.desktop" \
        --icon-file "$appdir/usr/share/icons/hicolor/512x512/apps/zara-re-platform.png" \
        --plugin qt \
        --output appimage
    popd >/dev/null
fi
