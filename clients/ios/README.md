# XZAP Client for iOS

## Requirements

- Mac with Xcode 15+
- Apple Developer Account ($99/year)
- iOS 16+ device

## Project Setup

1. Open Xcode → Create new project → App
   - Product Name: `XZAPClient`
   - Bundle ID: `com.xzap.client`
   - Interface: SwiftUI

2. Add Network Extension target:
   - File → New → Target → Network Extension
   - Product Name: `XZAPTunnel`
   - Bundle ID: `com.xzap.client.tunnel`
   - Provider Type: Packet Tunnel Provider

3. Copy source files:
   - `Sources/App/*` → main app target
   - `Sources/Tunnel/*` → tunnel extension target
   - `Sources/Shared/*` → both targets (add to both target memberships)

4. Enable capabilities (both targets):
   - App Groups: `group.com.xzap.client`
   - Network Extensions: Packet Tunnel

5. In main app target → Signing & Capabilities:
   - Personal VPN

## Build & Run

```bash
# Build from command line
xcodebuild -scheme XZAPClient -destination 'platform=iOS,name=iPhone' build

# Or open in Xcode and run on device (VPN doesn't work in simulator)
```

## Architecture

```
iOS App (SwiftUI UI)
    ↓ NETunnelProviderManager
PacketTunnelProvider (Network Extension)
    ↓ XzapTunnel (TLS + AES-256-GCM)
    ↓ NWConnection to XZAP server
Tokyo VPS → target website
```

## Note

The Packet Tunnel Provider needs a tun2socks implementation to convert
IP packets from the TUN interface into TCP connections that can be piped
through XZAP tunnels. Consider using:
- [Tun2SocksKit](https://github.com/niclas-eich/Tun2SocksKit) (Swift wrapper)
- Or implement a lightweight userspace TCP stack
