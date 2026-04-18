#!/bin/bash
# Build xzapcore.aar from the Go core (uTLS + mux + tun2socks fork).
# Produces /clients/android/app/libs/xzapcore.aar which the gradle build
# picks up automatically.
#
# Prerequisites:
#   - Go 1.22+ on PATH
#   - Android SDK + NDK (ANDROID_HOME pointing at the SDK, NDK in
#     $ANDROID_HOME/ndk/<version>/)
#
# On Windows: run in Git Bash or WSL. Set ANDROID_HOME to your SDK
# (e.g. C:/Users/<user>/AppData/Local/Android/Sdk).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$SCRIPT_DIR/../../core/go"
OUT="$SCRIPT_DIR/app/libs/xzapcore.aar"

if [ ! -d "$CORE_DIR" ]; then
    echo "core/go not found at $CORE_DIR"
    exit 1
fi

# Locate Android NDK
if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    if [ -d "${ANDROID_HOME:-}/ndk" ]; then
        ANDROID_NDK_HOME=$(ls -d "${ANDROID_HOME}/ndk"/*/ 2>/dev/null | head -1)
        ANDROID_NDK_HOME=${ANDROID_NDK_HOME%/}
        export ANDROID_NDK_HOME
    fi
fi

echo "Using:"
echo "  ANDROID_HOME=${ANDROID_HOME:-(unset)}"
echo "  ANDROID_NDK_HOME=${ANDROID_NDK_HOME:-(unset)}"

which go >/dev/null || { echo "Go not in PATH"; exit 1; }
go version

# Install gomobile/gobind if missing
go install golang.org/x/mobile/cmd/gomobile@latest
go install golang.org/x/mobile/cmd/gobind@latest
export PATH="$PATH:$(go env GOPATH)/bin"

cd "$CORE_DIR"
go get golang.org/x/mobile/bind 2>&1 | tail -3 || true
gomobile init

mkdir -p "$(dirname "$OUT")"
echo "Building xzapcore.aar (3-8 minutes)..."
gomobile bind -target=android -androidapi 24 -o "$OUT" ./mobile

ls -lh "$OUT"
echo ""
echo "=== SUCCESS ==="
echo "AAR: $OUT"
echo "Now rebuild the APK in Android Studio."
