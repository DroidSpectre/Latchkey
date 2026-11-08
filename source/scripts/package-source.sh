#!/bin/sh
# Package the exact source tree for a release. Excludes build output, the
# debug keystore, and the bundled Android tools (aapt2/r8 are environment
# dependencies, not source).
set -e
ROOT="$1"
TAG="$2"
NAME="$3"
CODE="$4"
OUT="$5"
[ -n "$ROOT" ] && [ -n "$TAG" ] && [ -n "$NAME" ] && [ -n "$CODE" ] && [ -n "$OUT" ] || {
  echo "usage: package-source.sh <root> <tag> <versionName> <versionCode> <out.tar.gz>" >&2
  exit 2
}
[ -d "$ROOT/android/app/src/main" ] || { echo "missing Android source: $ROOT/android/app/src/main" >&2; exit 1; }
mkdir -p "$(dirname "$OUT")"
STAGE_ROOT="$ROOT/build/nogradle/source-stage"
STAGE="$STAGE_ROOT/Latchkey-$TAG"
rm -rf "$STAGE"
mkdir -p "$STAGE/android/app/src"
cp -a "$ROOT/android/app/src/main" "$STAGE/android/app/src/"
for dir in client scripts tests docs bin; do
  [ -d "$ROOT/$dir" ] && cp -a "$ROOT/$dir" "$STAGE/"
done
for file in README.md PLAN.md SECURITY.md VERSIONS.md GROK_NOTES.md \
            FULL_ACCESS_PROBE_REPORT.md next-version.properties Dockerfile; do
  [ -f "$ROOT/$file" ] && cp -a "$ROOT/$file" "$STAGE/"
done
cat > "$STAGE/SOURCE.txt" <<EOF
Latchkey source archive
=======================
Tag:          $TAG
versionName:  $NAME
versionCode:  $CODE
Packaged:     $(date -u '+%Y-%m-%dT%H:%M:%SZ')

This is the source used to build the APK in this release directory. It is
complete except for the excluded items below.

Included:
  android/app/src/main/   Android app, manifest, Java, resources
  client/                 dependency-free Node client
  scripts/                Gradle-free build and packaging scripts
  tests/                  self-test and crypto interop harness
  docs/                   protocol and transport plans
  bin/                    latchkey launcher
  README.md PLAN.md SECURITY.md VERSIONS.md GROK_NOTES.md
  FULL_ACCESS_PROBE_REPORT.md next-version.properties Dockerfile

Excluded:
  debug.keystore          local debug signing key (never publish)
  .toolchain/             downloaded Android SDK (fetch-toolchain.sh)
  tools/aapt2             optional vendored Android build tool
  tools/r8.jar            optional vendored D8/R8 jar
  build/                  build output
  release APK/source copies

Build requirements:
  JDK 17 and Android SDK platform android-35 plus build-tools 35
  (aapt2, d8.jar, zipalign, apksigner). Run scripts/fetch-toolchain.sh
  or use the Dockerfile. The build script discovers JAVA_HOME,
  ANDROID_SDK_ROOT / ANDROID_HOME, and build-tools. Overrides:
  AAPT2, R8JAR, ANDROID_JAR, ZIPALIGN, APKSIGNER.

The SHA-256 lines in README.md, SECURITY.md, and VERSIONS.md describe the
published APK. Those files are not inputs to aapt/javac, so editing only
the recorded hash does not change the APK.

Source is provided as a snapshot, not a git repository. Preserve SHA-256
hashes in the release SHA256SUMS file when sharing.
EOF
tar --sort=name --owner=0 --group=0 --numeric-owner \
    -czf "$OUT" -C "$STAGE_ROOT" "Latchkey-$TAG"
sha256sum "$OUT"
