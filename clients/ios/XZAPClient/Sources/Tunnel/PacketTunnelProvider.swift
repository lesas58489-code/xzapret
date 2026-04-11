import NetworkExtension
import os.log

/// NEPacketTunnelProvider — intercepts all device traffic and routes through XZAP.
///
/// iOS VPN architecture:
///   All apps → TUN interface → PacketTunnelProvider → XZAP tunnel → VPS → internet
class PacketTunnelProvider: NEPacketTunnelProvider {

    private let log = OSLog(subsystem: "com.xzap.tunnel", category: "tunnel")
    private var crypto: XzapCrypto?
    private var tunnel: XzapTunnel?

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        os_log("Starting XZAP tunnel", log: log, type: .info)

        guard let config = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration,
              let server = config["server"] as? String,
              let portNum = config["port"] as? Int,
              let keyB64 = config["key"] as? String else {
            completionHandler(XzapError.handshakeFailed("Missing configuration"))
            return
        }

        let useTLS = config["tls"] as? Bool ?? true
        let crypto = XzapCrypto(base64Key: keyB64)
        self.crypto = crypto
        self.tunnel = XzapTunnel(
            serverHost: server,
            serverPort: UInt16(portNum),
            crypto: crypto,
            useTLS: useTLS
        )

        // Configure TUN interface
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: server)
        settings.ipv4Settings = NEIPv4Settings(addresses: ["10.255.0.1"], subnetMasks: ["255.255.255.0"])
        settings.ipv4Settings?.includedRoutes = [NEIPv4Route.default()]
        settings.dnsSettings = NEDNSSettings(servers: ["8.8.8.8", "1.1.1.1"])
        settings.mtu = 1500 as NSNumber

        setTunnelNetworkSettings(settings) { error in
            if let error = error {
                os_log("Failed to set tunnel settings: %{public}@", log: self.log, type: .error, error.localizedDescription)
                completionHandler(error)
                return
            }

            os_log("XZAP tunnel started -> %{public}@:%d", log: self.log, type: .info, server, portNum)
            completionHandler(nil)

            // Start reading packets from TUN
            self.readPackets()
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        os_log("Stopping XZAP tunnel (reason=%d)", log: log, type: .info, reason.rawValue)
        tunnel = nil
        crypto = nil
        completionHandler()
    }

    private func readPackets() {
        packetFlow.readPackets { [weak self] packets, protocols in
            for (i, packet) in packets.enumerated() {
                self?.handlePacket(packet, protocolFamily: protocols[i])
            }
            // Continue reading
            self?.readPackets()
        }
    }

    private func handlePacket(_ packet: Data, protocolFamily: NSNumber) {
        // TODO: Implement tun2socks or userspace TCP stack
        // For production: use a library like tun2socks to convert
        // IP packets to TCP connections, then pipe through XZAP tunnel.
        //
        // Each TCP connection from tun2socks → XzapTunnel.connect() → pipe data
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        // Handle messages from the main app (status queries etc.)
        if let msg = String(data: messageData, encoding: .utf8) {
            if msg == "status" {
                let status = tunnel != nil ? "connected" : "disconnected"
                completionHandler?(status.data(using: .utf8))
                return
            }
        }
        completionHandler?(nil)
    }
}
