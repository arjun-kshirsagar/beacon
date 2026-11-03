#!/bin/sh
# Builds android/app/libs/core.aar from ./mobile with the gomobile and gobind
# versions pinned in go.mod. Needs the Android SDK and NDK; set ANDROID_HOME
# (default ~/Library/Android/sdk) and optionally ANDROID_NDK_HOME.
set -eu
cd "$(dirname "$0")/.."
: "${ANDROID_HOME:=$HOME/Library/Android/sdk}"
if [ -z "${ANDROID_NDK_HOME:-}" ]; then
	ANDROID_NDK_HOME=$(ls -d "$ANDROID_HOME"/ndk/* 2>/dev/null | sort -V | tail -1)
fi
export ANDROID_HOME ANDROID_NDK_HOME
bin=$(mktemp -d)
trap 'rm -rf "$bin"' EXIT
GOBIN=$bin go install golang.org/x/mobile/cmd/gomobile golang.org/x/mobile/cmd/gobind
mkdir -p android/app/libs
PATH="$bin:$PATH" gomobile bind -target=android -androidapi 26 -javapkg=org.beacon \
	-o android/app/libs/core.aar ./mobile
echo "built android/app/libs/core.aar"
