#!/bin/bash
# Build XZAP Client .app for macOS
# Requirements: pip3 install pyinstaller cryptography

set -e
cd "$(dirname "$0")/../.."

echo "Building XZAP Client for macOS..."

pyinstaller --onefile --windowed \
    --name "XZAP Client" \
    --add-data "lists:lists" \
    --add-data "xzap:xzap" \
    --hidden-import xzap.client \
    --hidden-import xzap.tunnel \
    --hidden-import xzap.crypto \
    --hidden-import xzap.socks5 \
    --hidden-import xzap.routing \
    --hidden-import xzap.tls \
    --hidden-import xzap.transport.fragmented \
    --hidden-import xzap.transport.tcp \
    --hidden-import cryptography.hazmat.primitives.ciphers.aead \
    clients/windows/xzap_client.pyw

echo ""
if [ -d "dist/XZAP Client.app" ]; then
    echo "SUCCESS: dist/XZAP Client.app"
elif [ -f "dist/XZAP Client" ]; then
    echo "SUCCESS: dist/XZAP Client"
fi
