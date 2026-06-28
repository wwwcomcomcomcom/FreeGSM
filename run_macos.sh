#!/bin/bash
# FreeGSM (macOS, DoH-only) launcher.
#
# Sets up a local .venv with the macOS dependencies (no pydivert), then runs the
# resolver as root (binding 127.0.0.1:53 and repointing the system DNS both need
# it). Ctrl+C stops it and restores the original DNS.
#
# DoH upstream / other tunables can be overridden via the FREEGSM_* env vars,
# which `sudo -E` below forwards into the root process, e.g.:
#   FREEGSM_DOH_URL=https://8.8.8.8/dns-query ./run_macos.sh
set -euo pipefail
cd "$(dirname "$0")"

VENV=.venv
if [ ! -x "$VENV/bin/python3" ]; then
  echo "Creating virtualenv in $VENV ..."
  python3 -m venv "$VENV"
fi

# Dependency setup runs as the normal user (never pip-install as root).
"$VENV/bin/pip" install -q --upgrade pip
"$VENV/bin/pip" install -q -r requirements-macos.txt

# tun2socks powers the SNI/443 DPI bypass (utun -> local SOCKS proxy). It has no
# brew formula, so fetch the pinned release binary into ./bin if it's missing.
# Set FREEGSM_DPI=0 to skip the bypass (DoH only) and not need it.
TUN2SOCKS_VER=v2.6.0
mkdir -p bin
if [ ! -x bin/tun2socks ] && ! command -v tun2socks >/dev/null 2>&1; then
  case "$(uname -m)" in
    arm64) TS_ARCH=arm64 ;;
    x86_64) TS_ARCH=amd64 ;;
    *) TS_ARCH="" ;;
  esac
  if [ -n "$TS_ARCH" ]; then
    echo "Fetching tun2socks $TUN2SOCKS_VER (darwin-$TS_ARCH) into ./bin ..."
    URL="https://github.com/xjasonlyu/tun2socks/releases/download/$TUN2SOCKS_VER/tun2socks-darwin-$TS_ARCH.zip"
    if curl -fsSL "$URL" -o bin/tun2socks.zip; then
      (cd bin && unzip -oq tun2socks.zip && mv -f "tun2socks-darwin-$TS_ARCH" tun2socks && rm -f tun2socks.zip)
      xattr -c bin/tun2socks 2>/dev/null || true
      chmod +x bin/tun2socks
    else
      echo "  download failed; SNI bypass will be disabled (DoH still works)."
    fi
  fi
fi

echo "Starting FreeGSM (macOS). Requires sudo: binds :53, changes system DNS,"
echo "and (DPI on) creates a utun + default route. Ctrl+C restores everything."
exec sudo -E "$PWD/$VENV/bin/python3" -m dohproxy.macos.main
