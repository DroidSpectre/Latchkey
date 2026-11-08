#!/bin/sh
# Gradle-free APK build for Latchkey.
# Pipeline: aapt2 compile/link (+R.java) -> javac -> D8 -> zip dex ->
#           zipalign -> apksigner -> publish to /sdcard/Download/Latchkey
#           when that directory exists.
#
# Tool locations are discovered. Override any of them:
#   JAVA_HOME, ANDROID_SDK_ROOT (or ANDROID_HOME), BUILD_TOOLS,
#   AAPT2, R8JAR, ANDROID_JAR, ZIPALIGN, APKSIGNER
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="$ROOT/android/app/src/main"
OUT="$ROOT/build/nogradle"

if [ -z "$JAVA_HOME" ] || [ ! -x "$JAVA_HOME/bin/javac" ]; then
  JAVA_HOME=""
  for candidate in \
      /usr/lib/jvm/java-17-openjdk-amd64 \
      /usr/lib/jvm/java-17-openjdk-arm64 \
      /usr/lib/jvm/java-17-openjdk
  do
    if [ -x "$candidate/bin/javac" ]; then
      JAVA_HOME="$candidate"
      break
    fi
  done
fi
if [ -z "$JAVA_HOME" ] || [ ! -x "$JAVA_HOME/bin/javac" ]; then
  if command -v javac >/dev/null 2>&1; then
    JAVA_HOME="$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")"
  fi
fi
[ -n "$JAVA_HOME" ] && [ -x "$JAVA_HOME/bin/javac" ] || {
  echo "JDK 17 not found. Set JAVA_HOME." >&2
  exit 1
}
export JAVA_HOME
export PATH="$JAVA_HOME/bin:$PATH"

SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
if [ -z "$SDK_ROOT" ]; then
  if [ -d "$ROOT/.toolchain/platforms" ] || [ -d "$ROOT/.toolchain/build-tools" ]; then
    SDK_ROOT="$ROOT/.toolchain"
  elif [ -d /opt/android-sdk ]; then
    SDK_ROOT="/opt/android-sdk"
  fi
fi

if [ -z "$BUILD_TOOLS" ] && [ -n "$SDK_ROOT" ]; then
  if [ -d "$SDK_ROOT/build-tools/35.0.0" ]; then
    BUILD_TOOLS="$SDK_ROOT/build-tools/35.0.0"
  else
    BUILD_TOOLS="$(find "$SDK_ROOT/build-tools" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort -V | tail -n 1)"
  fi
fi

if [ -z "$AAPT2" ]; then
  if [ -x "$ROOT/tools/aapt2" ]; then
    AAPT2="$ROOT/tools/aapt2"
  elif [ -n "$BUILD_TOOLS" ] && [ -x "$BUILD_TOOLS/aapt2" ]; then
    AAPT2="$BUILD_TOOLS/aapt2"
  fi
fi
if [ -z "$R8JAR" ]; then
  if [ -f "$ROOT/tools/r8.jar" ]; then
    R8JAR="$ROOT/tools/r8.jar"
  elif [ -n "$BUILD_TOOLS" ] && [ -f "$BUILD_TOOLS/lib/d8.jar" ]; then
    R8JAR="$BUILD_TOOLS/lib/d8.jar"
  fi
fi
if [ -z "$ANDROID_JAR" ] && [ -n "$SDK_ROOT" ]; then
  ANDROID_JAR="$SDK_ROOT/platforms/android-35/android.jar"
fi
if [ -z "$ZIPALIGN" ]; then
  if [ -n "$BUILD_TOOLS" ] && [ -x "$BUILD_TOOLS/zipalign" ]; then
    ZIPALIGN="$BUILD_TOOLS/zipalign"
  elif command -v zipalign >/dev/null 2>&1; then
    ZIPALIGN="$(command -v zipalign)"
  fi
fi
if [ -z "$APKSIGNER" ]; then
  if [ -n "$BUILD_TOOLS" ] && [ -x "$BUILD_TOOLS/apksigner" ]; then
    APKSIGNER="$BUILD_TOOLS/apksigner"
  elif command -v apksigner >/dev/null 2>&1; then
    APKSIGNER="$(command -v apksigner)"
  fi
fi

KS="$ROOT/debug.keystore"
KS_PASS="latchkey"
KS_ALIAS="latchkey"

[ -n "$AAPT2" ] && [ -x "$AAPT2" ] || chmod +x "$AAPT2" 2>/dev/null || true
[ -n "$AAPT2" ] && [ -x "$AAPT2" ] || { echo "aapt2 not executable: ${AAPT2:-<unset>}" >&2; exit 1; }
[ -n "$R8JAR" ] && [ -f "$R8JAR" ] || { echo "r8/d8 jar missing: ${R8JAR:-<unset>}" >&2; exit 1; }
[ -n "$ANDROID_JAR" ] && [ -f "$ANDROID_JAR" ] || { echo "android.jar missing: ${ANDROID_JAR:-<unset>}" >&2; exit 1; }
[ -n "$ZIPALIGN" ] && [ -x "$ZIPALIGN" ] || { echo "zipalign missing: ${ZIPALIGN:-<unset>}" >&2; exit 1; }
[ -n "$APKSIGNER" ] && [ -x "$APKSIGNER" ] || { echo "apksigner missing: ${APKSIGNER:-<unset>}" >&2; exit 1; }

echo "java:      $JAVA_HOME"
echo "aapt2:     $AAPT2"
echo "d8/r8:     $R8JAR"
echo "android:   $ANDROID_JAR"
echo "zipalign:  $ZIPALIGN"
echo "apksigner: $APKSIGNER"

CODE="$(grep '^versionCode=' "$ROOT/next-version.properties" | cut -d= -f2)"
NAME="$(grep '^versionName=' "$ROOT/next-version.properties" | cut -d= -f2)"
MF_CODE="$(grep -o 'android:versionCode="[0-9]*"' "$APP/AndroidManifest.xml" | head -n 1 | cut -d'"' -f2)"
MF_NAME="$(grep -o 'android:versionName="[^"]*"' "$APP/AndroidManifest.xml" | head -n 1 | cut -d'"' -f2)"
[ "$MF_CODE" = "$CODE" ] && [ "$MF_NAME" = "$NAME" ] || {
  echo "VERSION MISMATCH: manifest $MF_NAME/$MF_CODE, properties $NAME/$CODE" >&2
  exit 1
}
SRC_NAME="$(grep -o 'VERSION = "[^"]*"' "$APP/java/io/latchkey/bridge/ServerRuntime.java" | head -n 1 | cut -d'"' -f2)"
[ "$SRC_NAME" = "$NAME" ] || {
  echo "VERSION MISMATCH: ServerRuntime.VERSION=$SRC_NAME, properties $NAME" >&2
  exit 1
}

# versionCode must never be reused: it is the only identity Android compares.
DEST="/sdcard/Download/Latchkey"
if [ -d /sdcard/Download ]; then
  mkdir -p "$DEST/releases"
  for existing in "$DEST"/releases/*; do
    [ -e "$existing" ] || continue
    base="$(basename "$existing")"
    case "$base" in
      *"+$CODE"|*"+$CODE"-r*)
        echo "REFUSING TO PUBLISH: versionCode $CODE already exists ($base)." >&2
        echo "Bump versionCode and versionName in next-version.properties and AndroidManifest.xml." >&2
        exit 1
        ;;
    esac
  done
fi

TAG="v${NAME}+${CODE}"
APK="$ROOT/build/nogradle/Latchkey-${TAG}.apk"

rm -rf "$OUT"
mkdir -p "$OUT/res" "$OUT/gen" "$OUT/classes" "$OUT/dex"

echo "[1/7] aapt2 compile resources"
"$AAPT2" compile --dir "$APP/res" -o "$OUT/res"

echo "[2/7] aapt2 link + R.java"
"$AAPT2" link \
  -o "$OUT/base.apk" \
  -I "$ANDROID_JAR" \
  --manifest "$APP/AndroidManifest.xml" \
  --min-sdk-version 26 \
  --target-sdk-version 35 \
  --java "$OUT/gen" \
  -R "$OUT/res"/*.flat

echo "[3/7] javac"
find "$APP/java" "$OUT/gen" -name '*.java' > "$OUT/sources.txt"
javac -source 8 -target 8 -encoding UTF-8 -Xlint:-options \
  -cp "$ANDROID_JAR" -d "$OUT/classes" @"$OUT/sources.txt"

echo "[4/7] D8 dex"
java -cp "$R8JAR" com.android.tools.r8.D8 \
  --lib "$ANDROID_JAR" --min-api 26 --output "$OUT/dex" \
  $(find "$OUT/classes" -name '*.class')

echo "[5/7] package + keystore"
cp "$OUT/base.apk" "$OUT/unsigned.apk"
if command -v zip >/dev/null 2>&1; then
  (cd "$OUT" && zip -qj unsigned.apk dex/classes.dex)
else
  # zip(1) is not part of a minimal JDK image. Match zip's default deflate.
  python3 - "$OUT/unsigned.apk" "$OUT/dex/classes.dex" <<'PY'
import sys, zipfile
apk, dex = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(apk, "a") as z:
    z.write(dex, "classes.dex", compress_type=zipfile.ZIP_DEFLATED)
PY
fi
if [ ! -f "$KS" ]; then
  keytool -genkeypair -keystore "$KS" -alias "$KS_ALIAS" \
    -storepass "$KS_PASS" -keypass "$KS_PASS" \
    -keyalg RSA -keysize 2048 -validity 10950 \
    -dname "CN=Latchkey Debug,O=Latchkey,C=US"
fi

echo "[6/7] zipalign"
"$ZIPALIGN" -f 4 "$OUT/unsigned.apk" "$OUT/aligned.apk"
"$ZIPALIGN" -c 4 "$OUT/aligned.apk"

echo "[7/7] sign + verify"
"$APKSIGNER" sign --ks "$KS" --ks-key-alias "$KS_ALIAS" \
  --ks-pass "pass:$KS_PASS" --key-pass "pass:$KS_PASS" \
  --out "$APK" "$OUT/aligned.apk"
"$APKSIGNER" verify --print-certs "$APK"

echo
echo "APK: $APK"
sha256sum "$APK"

SOURCE="$OUT/Latchkey-${TAG}-source.tar.gz"
echo "Source: $SOURCE"
sh "$ROOT/scripts/package-source.sh" "$ROOT" "$TAG" "$NAME" "$CODE" "$SOURCE"

DEST="/sdcard/Download/Latchkey"
if [ -d /sdcard/Download ]; then
  RELEASE="$DEST/releases/$TAG"
  mkdir -p "$RELEASE"
  cp "$APK" "$RELEASE/"
  cp "$SOURCE" "$RELEASE/"
  cat > "$RELEASE/INSTALL.txt" <<EOF
Latchkey $TAG
==============

Version: $NAME (versionCode $CODE)

1. Tap the APK and allow install from this source if prompted.
2. Open Latchkey.
3. Tap Grant and enable "Allow access to manage all files".
4. Tap Start server.
5. Tap Pair assistant (this copies a 2-minute, single-use link).
6. In the proot shell, run:  node /root/Latchkey/client/latchkey.mjs pair --clipboard
7. Then use the client without a key:  latchkey ls /sdcard

Source archive: $(basename "$SOURCE")
The legacy key is still available for older clients.
The server listens only on 127.0.0.1:39401.

Signing: debug.keystore (alias latchkey). If this APK was signed with a
different key than the copy already installed, uninstall Latchkey first.
Uninstalling clears paired clients and the legacy key.

If the phone reboots, open Latchkey and start the server again.
EOF
  (cd "$RELEASE" && sha256sum "$(basename "$APK")" "$(basename "$SOURCE")" > SHA256SUMS)
  # Keep a copy at the top level for easy tapping/sharing.
  cp "$APK" "$DEST/"
  cp "$SOURCE" "$DEST/"
  echo "published: $RELEASE"
else
  echo "WARNING: /sdcard/Download not available; APK left in $APK" >&2
fi
