#!/bin/bash
# Build tun2socks AAR for Android
# Run on machine with Go 1.22+ and Android SDK/NDK
#
# On Windows (Git Bash / WSL):
#   1. Install Go: https://go.dev/dl/
#   2. Set ANDROID_HOME=C:\Users\<user>\AppData\Local\Android\Sdk
#   3. Run: bash build_tun2socks.sh

set -e

echo "=== Building tun2socks AAR ==="

# Check prerequisites
which go || { echo "Go not found. Install from https://go.dev/dl/"; exit 1; }
go version

# Install gomobile
go install golang.org/x/mobile/cmd/gomobile@latest
go install golang.org/x/mobile/cmd/gobind@latest
export PATH=$PATH:$(go env GOPATH)/bin
gomobile init

# Clone tun2socks
TMPDIR=$(mktemp -d)
cd "$TMPDIR"
git clone --depth 1 https://github.com/xjasonlyu/tun2socks.git
cd tun2socks

# Build AAR
echo "Building AAR (this takes 2-5 minutes)..."
gomobile bind -target=android -androidapi 21 -o tun2socks.aar ./engine

# Copy to project
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$SCRIPT_DIR/app/libs"
cp tun2socks.aar "$SCRIPT_DIR/app/libs/"
echo ""
echo "=== SUCCESS ==="
echo "AAR copied to: app/libs/tun2socks.aar"
echo "Now rebuild the APK in Android Studio."

# Cleanup
rm -rf "$TMPDIR"
