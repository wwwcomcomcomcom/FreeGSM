#!/bin/bash
# Build a redistributable FreeGSM.pkg for macOS.
#
#   bash packaging/build_macos_pkg.sh
#
# Unlike build_macos_app.sh (which bakes in this repo's paths for personal use),
# this produces a SELF-CONTAINED app installed to /Applications via a .pkg:
#   * the app logic is a PyInstaller standalone binary (bundles Python + deps),
#   * tun2socks ships inside the bundle,
#   * paths are the fixed install location, so it runs on any Mac.
#
# Double-click the installed app to toggle FreeGSM on/off (admin password = UAC).
# The .pkg/app are ad-hoc signed (required to run on Apple Silicon) but NOT
# notarized -- distributing to others still needs an Apple Developer ID +
# notarization, else Gatekeeper warns (right-click > Open, or the .pkg's
# postinstall clears quarantine on this machine).
set -euo pipefail
export COPYFILE_DISABLE=1   # don't let cp/tar emit ._ AppleDouble files
cd "$(dirname "$0")/.."
PROJECT="$PWD"
PY="$PROJECT/.venv/bin/python3"
VERSION=1.0
IDENT=com.freegsm
INSTALL_APP="/Applications/FreeGSM.app"
STAGE="$PROJECT/dist/pkgroot"
APP="$STAGE/Applications/FreeGSM.app"
RES="$APP/Contents/Resources"

# --- deps + standalone binary ----------------------------------------------
[ -x "$PY" ] || { echo "Creating venv..."; python3 -m venv "$PROJECT/.venv"; }
"$PY" -m pip install -q --upgrade pip
"$PY" -m pip install -q -r requirements-macos.txt pyinstaller

echo "Building standalone binary (PyInstaller)..."
"$PY" -m PyInstaller --onefile --name freegsm --clean --noconfirm \
  --collect-submodules h2 --collect-submodules hpack --collect-submodules hyperframe \
  run_macos.py >/dev/null
[ -x "$PROJECT/dist/freegsm" ] || { echo "PyInstaller build failed"; exit 1; }

# --- tun2socks --------------------------------------------------------------
TS="$PROJECT/bin/tun2socks"
if [ ! -x "$TS" ]; then
  echo "Fetching tun2socks..."
  mkdir -p "$PROJECT/bin"
  case "$(uname -m)" in arm64) A=arm64 ;; x86_64) A=amd64 ;; *) A="" ;; esac
  curl -fsSL "https://github.com/xjasonlyu/tun2socks/releases/download/v2.6.0/tun2socks-darwin-$A.zip" -o "$PROJECT/bin/t.zip"
  (cd "$PROJECT/bin" && unzip -oq t.zip && mv -f "tun2socks-darwin-$A" tun2socks && rm -f t.zip)
  chmod +x "$TS"
fi

# --- assemble the self-contained .app --------------------------------------
rm -rf "$STAGE"; mkdir -p "$APP/Contents/MacOS" "$RES"
cp "$PROJECT/dist/freegsm" "$RES/freegsm"
cp "$TS" "$RES/tun2socks"
xattr -c "$RES/freegsm" "$RES/tun2socks" 2>/dev/null || true
chmod +x "$RES/freegsm" "$RES/tun2socks"

cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>FreeGSM</string>
  <key>CFBundleDisplayName</key><string>FreeGSM</string>
  <key>CFBundleIdentifier</key><string>com.freegsm.app</string>
  <key>CFBundleExecutable</key><string>FreeGSM</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleVersion</key><string>1.0</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
</dict></plist>
PLIST

# LaunchDaemon -> the bundled binary; tun2socks path is the fixed install dir.
cat > "$RES/com.freegsm.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.freegsm</string>
  <key>ProgramArguments</key><array>
    <string>$INSTALL_APP/Contents/Resources/freegsm</string>
  </array>
  <key>EnvironmentVariables</key><dict>
    <key>FREEGSM_TUN2SOCKS</key><string>$INSTALL_APP/Contents/Resources/tun2socks</string>
  </dict>
  <key>StandardOutPath</key><string>/var/log/freegsm.log</string>
  <key>StandardErrorPath</key><string>/var/log/freegsm.log</string>
  <key>RunAtLoad</key><true/>
  <key>ProcessType</key><string>Interactive</string>
</dict></plist>
PLIST

cat > "$RES/freegsm-toggle.sh" <<'TOGGLE'
#!/bin/bash
# Toggle FreeGSM on/off via launchd. Run as root by the app launcher.
LABEL=com.freegsm
PLIST_SRC="$(cd "$(dirname "$0")" && pwd)/com.freegsm.plist"
PLIST=/Library/LaunchDaemons/com.freegsm.plist
if launchctl print system/$LABEL >/dev/null 2>&1; then
  launchctl bootout system/$LABEL 2>/dev/null
  rm -f "$PLIST"
  echo "FreeGSM stopped. DNS and routing restored."
else
  cp "$PLIST_SRC" "$PLIST"; chown root:wheel "$PLIST"; chmod 644 "$PLIST"
  launchctl bootstrap system "$PLIST" 2>/dev/null
  sleep 3
  if launchctl print system/$LABEL >/dev/null 2>&1; then
    echo "FreeGSM started. DNS upgraded to DoH; SNI/443 bypass active."
  else
    rm -f "$PLIST"; echo "FreeGSM failed to start. See /var/log/freegsm.log"
  fi
fi
TOGGLE
chmod +x "$RES/freegsm-toggle.sh"

cat > "$APP/Contents/MacOS/FreeGSM" <<'LAUNCH'
#!/bin/bash
SELF="$(cd "$(dirname "$0")" && pwd)"
TOGGLE="$SELF/../Resources/freegsm-toggle.sh"
RESULT=$(/usr/bin/osascript <<OSA 2>&1
set t to quoted form of "$TOGGLE"
do shell script "/bin/bash " & t & " 2>&1" with administrator privileges
OSA
)
/usr/bin/osascript -e "display dialog \"$RESULT\" buttons {\"OK\"} default button \"OK\" with title \"FreeGSM\" with icon note giving up after 8" >/dev/null 2>&1 || true
LAUNCH
chmod +x "$APP/Contents/MacOS/FreeGSM"

# --- ad-hoc sign (Apple Silicon requires at least an ad-hoc signature) ------
find "$STAGE" -name '._*' -delete 2>/dev/null || true   # drop AppleDouble litter
codesign --force --deep --sign - "$APP" 2>/dev/null || echo "warn: codesign failed (app may need right-click > Open)"
find "$STAGE" -name '._*' -delete 2>/dev/null || true

# --- postinstall: clear quarantine + re-sign on the target machine ----------
SCRIPTS="$PROJECT/dist/pkgscripts"; rm -rf "$SCRIPTS"; mkdir -p "$SCRIPTS"
cat > "$SCRIPTS/postinstall" <<'POST'
#!/bin/bash
APP=/Applications/FreeGSM.app
xattr -dr com.apple.quarantine "$APP" 2>/dev/null || true
codesign --force --deep --sign - "$APP" 2>/dev/null || true
exit 0
POST
chmod +x "$SCRIPTS/postinstall"

# --- build the pkg ----------------------------------------------------------
OUT="$PROJECT/dist/FreeGSM.pkg"
pkgbuild --root "$STAGE" --install-location / \
  --identifier "$IDENT.pkg" --version "$VERSION" \
  --scripts "$SCRIPTS" "$OUT" >/dev/null

echo "Built: $OUT"
echo "Install: double-click it (or: sudo installer -pkg $OUT -target /)."
echo "Then double-click /Applications/FreeGSM.app to toggle on/off."
