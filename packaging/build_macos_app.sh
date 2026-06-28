#!/bin/bash
# Build a double-clickable FreeGSM.app for macOS.
#
# The app is a TOGGLE: double-click once -> macOS asks for your admin password
# (the equivalent of Windows UAC) and FreeGSM starts (DoH + SNI/443 bypass);
# double-click again -> it stops and restores DNS/routing.
#
# It bakes in absolute paths to this repo, its .venv, and ./bin/tun2socks, so
# it's a personal launcher, not a redistributable bundle (that would need the
# venv/python/tun2socks bundled and code-signing). Output: dist/FreeGSM.app
set -euo pipefail
cd "$(dirname "$0")/.."
PROJECT="$PWD"
VENV="$PROJECT/.venv"
PY="$VENV/bin/python3"
TUN2SOCKS="$PROJECT/bin/tun2socks"
APP="$PROJECT/dist/FreeGSM.app"

# --- ensure deps exist (venv + macOS requirements + tun2socks) --------------
if [ ! -x "$PY" ]; then
  echo "Creating venv..."
  python3 -m venv "$VENV"
fi
"$PY" -m pip install -q --upgrade pip
"$PY" -m pip install -q -r requirements-macos.txt

if [ ! -x "$TUN2SOCKS" ] && ! command -v tun2socks >/dev/null 2>&1; then
  echo "Fetching tun2socks (for the SNI bypass)..."
  mkdir -p bin
  case "$(uname -m)" in arm64) A=arm64 ;; x86_64) A=amd64 ;; *) A="" ;; esac
  if [ -n "$A" ] && curl -fsSL \
      "https://github.com/xjasonlyu/tun2socks/releases/download/v2.6.0/tun2socks-darwin-$A.zip" \
      -o bin/tun2socks.zip; then
    (cd bin && unzip -oq tun2socks.zip && mv -f "tun2socks-darwin-$A" tun2socks && rm -f tun2socks.zip)
    xattr -c bin/tun2socks 2>/dev/null || true
    chmod +x bin/tun2socks
  else
    echo "  tun2socks unavailable; the app will run DoH-only."
  fi
fi
[ -x "$TUN2SOCKS" ] || TUN2SOCKS="tun2socks"  # fall back to PATH lookup

# --- bundle skeleton --------------------------------------------------------
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>FreeGSM</string>
  <key>CFBundleDisplayName</key><string>FreeGSM</string>
  <key>CFBundleIdentifier</key><string>com.freegsm.app</string>
  <key>CFBundleExecutable</key><string>FreeGSM</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleVersion</key><string>1.0</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
</dict>
</plist>
PLIST

# --- LaunchDaemon plist (baked paths) ---------------------------------------
# The app starts FreeGSM via launchd, not a backgrounded shell: under osascript
# "with administrator privileges" there is no controlling tty, so nohup-style
# detachment fails ("can't detach from console"). launchd owns the process, so
# it survives the auth dialog closing and is stopped cleanly with bootout
# (SIGTERM -> our graceful teardown -> DNS/routing restored).
cat > "$APP/Contents/Resources/com.freegsm.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.freegsm</string>
  <key>ProgramArguments</key>
  <array>
    <string>$PY</string><string>-m</string><string>dohproxy.macos.main</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PYTHONPATH</key><string>$PROJECT</string>
    <key>FREEGSM_TUN2SOCKS</key><string>$TUN2SOCKS</string>
  </dict>
  <key>WorkingDirectory</key><string>$PROJECT</string>
  <key>StandardOutPath</key><string>/var/log/freegsm.log</string>
  <key>StandardErrorPath</key><string>/var/log/freegsm.log</string>
  <key>RunAtLoad</key><true/>
  <key>ProcessType</key><string>Interactive</string>
</dict>
</plist>
PLIST

# --- privileged toggle (runs as root via the launcher) ----------------------
cat > "$APP/Contents/Resources/freegsm-toggle.sh" <<'TOGGLE'
#!/bin/bash
# Toggle FreeGSM on/off via launchd. Invoked as root by the app launcher.
LABEL=com.freegsm
PLIST_SRC="$(cd "$(dirname "$0")" && pwd)/com.freegsm.plist"
PLIST=/Library/LaunchDaemons/com.freegsm.plist

if launchctl print system/$LABEL >/dev/null 2>&1; then
  launchctl bootout system/$LABEL 2>/dev/null
  rm -f "$PLIST"
  echo "FreeGSM stopped. DNS and routing restored."
else
  cp "$PLIST_SRC" "$PLIST"
  chown root:wheel "$PLIST"; chmod 644 "$PLIST"
  launchctl bootstrap system "$PLIST" 2>/dev/null
  sleep 3
  if launchctl print system/$LABEL >/dev/null 2>&1; then
    echo "FreeGSM started. DNS upgraded to DoH; SNI/443 bypass active."
  else
    rm -f "$PLIST"
    echo "FreeGSM failed to start. See /var/log/freegsm.log"
  fi
fi
TOGGLE
chmod +x "$APP/Contents/Resources/freegsm-toggle.sh"

# --- launcher (double-clicked; elevates the toggle) -------------------------
cat > "$APP/Contents/MacOS/FreeGSM" <<'LAUNCH'
#!/bin/bash
SELF="$(cd "$(dirname "$0")" && pwd)"
TOGGLE="$SELF/../Resources/freegsm-toggle.sh"
RESULT=$(/usr/bin/osascript <<OSA 2>&1
set t to quoted form of "$TOGGLE"
do shell script "/bin/bash " & t & " 2>&1" with administrator privileges
OSA
)
/usr/bin/osascript -e "display notification \"$RESULT\" with title \"FreeGSM\"" >/dev/null 2>&1
/usr/bin/osascript -e "display dialog \"$RESULT\" buttons {\"OK\"} default button \"OK\" with title \"FreeGSM\" with icon note giving up after 8" >/dev/null 2>&1 || true
LAUNCH
chmod +x "$APP/Contents/MacOS/FreeGSM"

echo "Built: $APP"
echo "Double-click it to start (you'll be asked for your admin password);"
echo "double-click again to stop. Logs: /var/log/freegsm.log"
