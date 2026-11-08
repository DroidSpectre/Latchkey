# Reproducible Latchkey debug APK.
# Official Android build-tools are linux/amd64.
FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      openjdk-17-jdk-headless unzip curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . /src
RUN sh scripts/fetch-toolchain.sh \
 && sh scripts/build-apk-nogradle.sh

# Signed APK: /src/build/nogradle/Latchkey-v<versionName>+<versionCode>.apk
