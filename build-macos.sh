#!/bin/bash
set -euo pipefail
if [[ "$(uname -s)" != Darwin ]]; then
    echo 'macOS app builds require macOS and an Apple SDK.' >&2
    exit 1
fi
project_root="$(cd -- "$(dirname -- "$0")" && pwd)"
architecture="$(uname -m)"
if [[ $# -gt 0 ]]; then
    if [[ $# -ne 2 || "$1" != --arch ]]; then
        echo 'Usage: bash build-macos.sh [--arch arm64|x86_64|universal]' >&2
        exit 1
    fi
    architecture="$2"
fi
case "$architecture" in
    arm64|x86_64) cmake_arch="$architecture" ;;
    universal) cmake_arch='arm64;x86_64' ;;
    *) echo 'Unsupported architecture.' >&2; exit 1 ;;
esac
command -v cmake >/dev/null || { echo 'Install CMake before building.' >&2; exit 1; }
xcode-select -p >/dev/null
build_directory="$project_root/build-macos-$architecture"
umask 077
cmake -S "$project_root" -B "$build_directory" \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_OSX_DEPLOYMENT_TARGET=15.0 \
    "-DCMAKE_OSX_ARCHITECTURES=$cmake_arch" \
    -DOWNVPN_BUILD_WINDOWS_APP=OFF -DOWNVPN_BUILD_MACOS_APP=ON -DBUILD_TESTING=ON
cmake --build "$build_directory" --parallel 4
ctest --test-dir "$build_directory" --output-on-failure
version=0.6.0-alpha.1
destination="$project_root/dist/OwnVPN-Mac-$version-$architecture.app"
if [[ -e "$destination" ]]; then
    echo "Output already exists: $destination. Move the previous artifact before rebuilding." >&2
    exit 1
fi
mkdir -p "$project_root/dist"
ditto "$build_directory/src/platform/macos/OwnVPN.app" "$destination"
codesign --force --sign - --identifier com.ownvpn.macos "$destination"
codesign --verify --strict "$destination"
archive="$project_root/dist/OwnVPN-Mac-$version-$architecture.zip"
ditto -c -k --keepParent "$destination" "$archive"
(cd "$project_root/dist" && shasum -a 256 "$(basename "$archive")" > "$(basename "$archive").sha256")
echo "Built: $destination"
echo 'This development build does not yet establish a VPN tunnel.'
