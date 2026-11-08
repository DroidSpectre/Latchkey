#!/bin/sh
# Download a local Android SDK into .toolchain/ (or ANDROID_SDK_ROOT).
# Pins command-line tools build 15859902, platform android-35, build-tools 35.0.0.
# Idempotent: skips a package when its expected files are already present.
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SDK="${ANDROID_SDK_ROOT:-$ROOT/.toolchain}"
CTL_REV="${CMDTOOLS_REV:-15859902}"
URL="https://dl.google.com/android/repository/commandlinetools-linux-${CTL_REV}_latest.zip"

if [ -z "$JAVA_HOME" ] || [ ! -x "$JAVA_HOME/bin/java" ]; then
  for candidate in \
      /usr/lib/jvm/java-17-openjdk-amd64 \
      /usr/lib/jvm/java-17-openjdk-arm64 \
      /usr/lib/jvm/java-17-openjdk
  do
    if [ -x "$candidate/bin/java" ]; then
      JAVA_HOME="$candidate"
      break
    fi
  done
fi
[ -n "$JAVA_HOME" ] && [ -x "$JAVA_HOME/bin/java" ] || {
  echo "JDK 17 not found. Set JAVA_HOME." >&2
  exit 1
}
export JAVA_HOME
export PATH="$JAVA_HOME/bin:$PATH"

mkdir -p "$SDK"
if [ ! -x "$SDK/cmdline-tools/latest/bin/sdkmanager" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  echo "downloading commandlinetools $CTL_REV"
  curl -fL --retry 3 -o "$tmp/cmdtools.zip" "$URL"
  unzip -q "$tmp/cmdtools.zip" -d "$tmp"
  mkdir -p "$SDK/cmdline-tools"
  rm -rf "$SDK/cmdline-tools/latest"
  mv "$tmp/cmdline-tools" "$SDK/cmdline-tools/latest"
  rm -rf "$tmp"
  trap - EXIT
fi

SDKMANAGER="$SDK/cmdline-tools/latest/bin/sdkmanager"
# Non-interactive license accept. The hash is the standard Android SDK license.
mkdir -p "$SDK/licenses"
printf '%s\n' "24333f8a63b6825ea9c5514f83c2829b004d1fee" > "$SDK/licenses/android-sdk-license"

if [ ! -f "$SDK/platforms/android-35/android.jar" ] || [ ! -x "$SDK/build-tools/35.0.0/aapt2" ]; then
  echo "installing platforms;android-35 and build-tools;35.0.0"
  "$SDKMANAGER" --sdk_root="$SDK" "platforms;android-35" "build-tools;35.0.0"
fi

echo "toolchain: $SDK"
echo "android.jar: $SDK/platforms/android-35/android.jar"
echo "build-tools: $SDK/build-tools/35.0.0"
