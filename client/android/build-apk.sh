#!/usr/bin/env bash
# Baut site/lightningmail.apk ohne Gradle: PWA-dist bundlen, dann
# aapt2 → javac → d8 → zipalign → apksigner (SDK unter /config/android-sdk).
# SKIP_BUILD=1 nutzt das vorhandene client/app/dist ohne vite-Neubau.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
APP="$ROOT/client/app"
SDK=${ANDROID_SDK:-/config/android-sdk}
BT="$SDK/build-tools/34.0.0"
PLAT="$SDK/platforms/android-34/android.jar"
KS="$HERE/keystore.jks"
# Signier-Credential: kscred.dat wird beim ersten Build zufällig erzeugt.
# Zusammen mit keystore.jks aufbewahren — ohne beide kein Update installierbar!
KCRED="$HERE/kscred.dat"
[ -f "$KCRED" ] || openssl rand -hex 16 > "$KCRED"
chmod 600 "$KCRED"
KSP="$(tr -d '\n\r' < "$KCRED")"
OUT="$ROOT/site/lightningmail.apk"

cd "$HERE"
[ -f "$BT/aapt2" ] || { echo "✗ build-tools fehlen: $BT"; exit 1; }
[ -f "$PLAT" ]   || { echo "✗ android.jar fehlt: $PLAT"; exit 1; }

echo "== PWA bauen/bundlen"
[ "${SKIP_BUILD:-0}" = "1" ] || ( cd "$APP" && npx vite build )
[ -f "$APP/dist/index.html" ] || { echo "✗ kein $APP/dist — erst vite bauen"; exit 1; }

rm -rf build
mkdir -p build/gen build/classes build/dex build/assets
cp -r "$APP/dist/." build/assets/
rm -rf build/assets/keys   # Demo-Keys gehören nicht in die APK
# In der APK gibt es keinen lokalen /relay-* Proxy → absolute URLs
find build/assets -name '*.html' -exec sed -i \
  -e 's#value="/relay-a"#value="https://lightningmail.app/relay-a"#g' \
  -e 's#value="/relay-b"#value="https://lightningmail.app/relay-b"#g' \
  -e 's#href="/"#href="https://lightningmail.app/"#g' \
  -e 's#href="/forum"#href="https://lightningmail.app/forum"#g' \
  -e 's#href="/architecture"#href="https://lightningmail.app/architecture"#g' \
  -e 's#href="/impressum"#href="https://lightningmail.app/impressum"#g' {} +
grep -q 'value="https://lightningmail.app/relay-a"' build/assets/index.html \
  || { echo "✗ Relay-Rewrite fehlgeschlagen"; exit 1; }

echo "== aapt2 compile"
"$BT/aapt2" compile --dir res -o build/res.zip

echo "== aapt2 link"
"$BT/aapt2" link -o build/base.apk -I "$PLAT" \
  --manifest AndroidManifest.xml -A build/assets build/res.zip \
  --java build/gen --min-sdk-version 26 --target-sdk-version 34 --auto-add-overlay

echo "== javac"
javac -source 17 -target 17 -encoding UTF-8 -classpath "$PLAT" -d build/classes \
  $(find build/gen java -name "*.java")

echo "== d8"
"$BT/d8" --lib "$PLAT" --min-api 26 --output build/dex $(find build/classes -name "*.class")

echo "== classes.dex einpacken (vor zipalign/sign!)"
python3 - <<'PY'
import zipfile
z = zipfile.ZipFile('build/base.apk', 'a', zipfile.ZIP_DEFLATED)
z.write('build/dex/classes.dex', 'classes.dex')
z.close()
print('classes.dex eingepackt')
PY

echo "== zipalign"
"$BT/zipalign" -f 4 build/base.apk build/aligned.apk

if [ ! -f "$KS" ]; then
  keytool -genkeypair -v -keystore "$KS" -alias lightningmail -keyalg RSA -keysize 2048 \
    -validity 10000 -storepass "$KSP" -keypass "$KSP" \
    -dname "CN=LightningMail, O=LightningMail, C=DE" >/dev/null 2>&1
  echo "neuer Keystore: $KS (aufbewahren — ohne ihn kein Update installierbar!)"
fi

echo "== sign"
"$BT/apksigner" sign --ks "$KS" --ks-pass "pass:$KSP" --key-pass "pass:$KSP" \
  --out "$OUT" build/aligned.apk

echo "== verify"
"$BT/apksigner" verify --print-certs "$OUT" | head -4 || true
"$BT/aapt2" dump badging "$OUT" | head -12 || true
ls -la "$OUT"
echo "✓ $OUT"
