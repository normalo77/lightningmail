#!/usr/bin/env bash
# build-deb.sh — thin .deb for the lmdesk native desktop client.
# Runs ON the build host (e.g. Debian trixie LXC dev-sandbox, invoked via `pct exec`).
# "Thin" = only the binary + .desktop file + icons are packaged; GTK4,
# libadwaita and libwebkitgtk stay SYSTEM libraries (declared as Depends).
#
# Usage: REPO=<workspace> OUTDIR=<workspace>/out ./build-deb.sh [VERSION]
#        BIN=/path/to/prebuilt/lmdesk ./build-deb.sh   # skip the go build
set -euo pipefail

REPO="${REPO:-<workspace>}"
OUTDIR="${OUTDIR:-$REPO/out}"
VER="${1:-${VER:-1.0.6~m3}}"
PKG="lightningmail-desktop"
ARCH="${ARCH:-amd64}"

# fresh staging dir every run -> idempotent
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
ROOT="$WORK/$PKG"
mkdir -p "$ROOT/DEBIAN" \
         "$ROOT/usr/bin" \
         "$ROOT/usr/share/applications" \
         "$ROOT/usr/share/icons/hicolor/512x512/apps" \
         "$ROOT/usr/share/icons/hicolor/192x192/apps"

if [ -n "${BIN:-}" ]; then
  install -m 755 "$BIN" "$ROOT/usr/bin/lmdesk"
else
  ( cd "$REPO/desktop" && GOTOOLCHAIN=auto CGO_ENABLED=0 go build -o "$ROOT/usr/bin/lmdesk" ./cmd/lmdesk )
fi

ICONDIR="$REPO/client/app/public/icons"
[ -f "$ICONDIR/appicon-512.png" ] || { echo "ERROR: icons not found in $ICONDIR (transfer client/app/public/icons to $REPO)" >&2; exit 1; }
install -m 644 "$ICONDIR/appicon-512.png" "$ROOT/usr/share/icons/hicolor/512x512/apps/lightningmail.png"
install -m 644 "$ICONDIR/appicon-192.png" "$ROOT/usr/share/icons/hicolor/192x192/apps/lightningmail.png"

cat > "$ROOT/usr/share/applications/app.lightningmail.Desktop.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=lightningmail
Comment=Lightning-Mail-Client
Exec=lmdesk
Icon=lightningmail
Categories=Network;Email;
EOF

# exact runtime package names of Debian trixie (verified via dpkg -l on dev-sandbox)
cat > "$ROOT/DEBIAN/control" <<EOF
Package: $PKG
Version: $VER
Architecture: $ARCH
Maintainer: Bernd Holzer
Section: mail
Priority: optional
Depends: libgtk-4-1, libadwaita-1-0, libwebkitgtk-6.0-4
Description: lightningmail native desktop client
 Thin package: lmdesk binary, desktop entry and icons only.
 GTK4, libadwaita and libwebkitgtk are used as system libraries.
EOF

mkdir -p "$OUTDIR"
OUT="$OUTDIR/${PKG}_${VER}_${ARCH}.deb"
dpkg-deb -Zxz --root-owner-group --build "$ROOT" "$OUT"
echo "built: $OUT"
