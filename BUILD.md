# Building Latchkey 1.3.0-C (no Gradle)

Requirements: Linux x86_64 or arm64, JDK 17, curl, unzip, (zip optional), Node 18+ for tests.

    export JAVA_HOME=/path/to/jdk-17
    export ANDROID_SDK_ROOT=$PWD/.toolchain      # or an existing SDK
    sh scripts/fetch-toolchain.sh                # cmdline-tools 15859902, platform 35, build-tools 35.0.0
    sh scripts/build-apk-nogradle.sh             # -> build/nogradle/Latchkey-v1.3.0-C+20.apk
    node tests/selftest.mjs                      # protocol / crypto / client self-test

The build script creates `debug.keystore` (alias/password `latchkey`) if missing.
Never commit or distribute it; use a real release keystore for production.
Verified here with Eclipse Temurin JDK 17 and Android build-tools 35.0.0.
