#!/usr/bin/env bash
# build-appimage.sh — thin AppImage for the lmdesk native desktop client.
# Runs ON the build host (e.g. Debian trixie LXC CT114, invoked via `pct exec`).
# "Thin" = AppRun + binary + desktop entry + icon only; GTK4, libadwaita and
# libwebkitgtk stay SYSTEM libraries (nothing bundled).
#
# Usage: REPO=/root/lm-pack OUTDIR=/root/lm-pack/out ./build-appimage.sh [VERSION]
#        BIN=/path/to/prebuilt/lmdesk ./build-appimage.sh
set -euo pipefail

REPO="${REPO:-/root/lm-pack}"
OUTDIR="${OUTDIR:-$REPO/out}"
VER="${1:-${VER:-1.0.6~m3}}"
ARCH="x86_64"
TOOL="$REPO/tools/appimagetool-$ARCH.AppImage"
TOOL_URL="https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-$ARCH.AppImage"

# download appimagetool (cached in $REPO/tools -> idempotent)
if [ ! -x "$TOOL" ]; then
  curl -sfI -m 15 https://github.com >/dev/null || { echo "ERROR: no internet to github.com" >&2; exit 1; }
  mkdir -p "$(dirname "$TOOL")"
  curl -fL -m 300 -o "$TOOL" "$TOOL_URL"
  chmod +x "$TOOL"
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
APPDIR="$WORK/lightningmail.AppDir"
mkdir -p "$APPDIR/usr/bin" \
         "$APPDIR/usr/share/applications" \
         "$APPDIR/usr/share/icons/hicolor/512x512/apps"

if [ -n "${BIN:-}" ]; then
  install -m 755 "$BIN" "$APPDIR/usr/bin/lmdesk"
else
  ( cd "$REPO/desktop" && GOTOOLCHAIN=auto CGO_ENABLED=0 go build -o "$APPDIR/usr/bin/lmdesk" ./cmd/lmdesk )
fi

ICONDIR="$REPO/client/app/public/icons"
[ -f "$ICONDIR/appicon-512.png" ] || { echo "ERROR: icons not found in $ICONDIR (transfer client/app/public/icons to $REPO)" >&2; exit 1; }
install -m 644 "$ICONDIR/appicon-512.png" "$APPDIR/usr/share/icons/hicolor/512x512/apps/lightningmail.png"
# appimagetool resolves the icon from the AppDir root
cp "$APPDIR/usr/share/icons/hicolor/512x512/apps/lightningmail.png" "$APPDIR/lightningmail.png"

cat > "$APPDIR/lightningmail.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=lightningmail
Comment=Lightning-Mail-Client
Exec=lmdesk
Icon=lightningmail
Categories=Network;Email;
EOF
cp "$APPDIR/lightningmail.desktop" "$APPDIR/usr/share/applications/app.lightningmail.Desktop.desktop"

cat > "$APPDIR/AppRun" <<'EOF'
#!/bin/sh
# thin AppRun: system GTK4/libadwaita/libwebkitgtk, only lmdesk lives inside
HERE="$(dirname "$(readlink -f "$0")")"
exec "$HERE/usr/bin/lmdesk" "$@"
EOF
chmod +x "$APPDIR/AppRun"

mkdir -p "$OUTDIR"
OUT="$OUTDIR/lightningmail-desktop-${VER//\~/-}-$ARCH.AppImage"
# appimagetool is itself an AppImage; extract-and-run works with and without FUSE
export APPIMAGE_EXTRACT_AND_RUN=1
"$TOOL" "$APPDIR" "$OUT"   # appimagetool may print integration warnings; exit code is what matters
echo "built: $OUT"
