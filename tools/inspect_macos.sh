#!/bin/bash
set -euo pipefail
[[ "$(uname -s)" == Darwin ]] || { echo 'Run on the Mac.' >&2; exit 1; }
sw_vers
uname -m
xcode-select -p || true
xcrun --find clang++ || true
xcrun clang++ --version || true
if command -v cmake >/dev/null; then cmake --version; else echo 'CMake: not installed'; fi
for vpn_executable in /opt/homebrew/sbin/openvpn /usr/local/sbin/openvpn; do
    if [[ -x "$vpn_executable" ]]; then
        echo "OpenVPN: $vpn_executable"
        "$vpn_executable" --version | head -n 1
    fi
done
echo 'No VPN connection, configuration import, or Keychain write was performed.'
