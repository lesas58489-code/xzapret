import Foundation
import Network

/// XZAP Tunnel — connects to server, handshake, bidirectional pipe.
///
/// Wire format: [4B length][16B random prefix][AES-GCM encrypted data]
/// Fragmentation: [4B total][1B flags][data] for frames <= 150 bytes
class XzapTunnel {
    let serverHost: String
    let serverPort: UInt16
    let crypto: XzapCrypto
    let useTLS: Bool

    private static let prefixSize = 16
    private static let maxFrame = 256 * 1024
    private static let fragThreshold = 150
    private static let fragMin = 24
    private static let fragMax = 68

    private let whiteDomains = [
        "www.youtube.com", "www.google.com", "www.cloudflare.com",
        "www.microsoft.com", "www.apple.com", "www.amazon.com",
        "cdn.jsdelivr.net", "ajax.googleapis.com",
    ]

    init(serverHost: String, serverPort: UInt16, crypto: XzapCrypto, useTLS: Bool = true) {
        self.serverHost = serverHost
        self.serverPort = serverPort
        self.crypto = crypto
        self.useTLS = useTLS
    }

    /// Open tunnel to target through XZAP server.
    func connect(targetHost: String, targetPort: UInt16,
                 completion: @escaping (Result<TunnelConnection, Error>) -> Void) {
        let sni = whiteDomains.randomElement()!

        let params: NWParameters
        if useTLS {
            let tlsOptions = NWProtocolTLS.Options()
            // Trust all certs (XZAP verifies via shared key)
            sec_protocol_options_set_verify_block(
                tlsOptions.securityProtocolOptions, { _, _, completion in
                    completion(true)
                }, DispatchQueue.global()
            )
            // Set SNI for anti-DPI
            sec_protocol_options_set_tls_server_name(
                tlsOptions.securityProtocolOptions, sni
            )
            params = NWParameters(tls: tlsOptions)
        } else {
            params = .tcp
        }

        params.requiredInterfaceType = .other
        let connection = NWConnection(
            host: NWEndpoint.Host(serverHost),
            port: NWEndpoint.Port(rawValue: serverPort)!,
            using: params
        )

        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                self?.performHandshake(connection: connection,
                                       targetHost: targetHost,
                                       targetPort: targetPort,
                                       completion: completion)
            case .failed(let error):
                completion(.failure(error))
            default:
                break
            }
        }

        connection.start(queue: .global(qos: .userInitiated))
    }

    private func performHandshake(connection: NWConnection,
                                   targetHost: String,
                                   targetPort: UInt16,
                                   completion: @escaping (Result<TunnelConnection, Error>) -> Void) {
        // Send CONNECT request
        let req: [String: Any] = [
            "cmd": "connect",
            "host": targetHost,
            "port": Int(targetPort)
        ]
        guard let reqData = try? JSONSerialization.data(withJSONObject: req) else {
            completion(.failure(XzapError.handshakeFailed("JSON encode failed")))
            return
        }

        do {
            let frame = try buildFrame(reqData)
            sendFragmented(connection: connection, data: frame) { [weak self] error in
                if let error = error {
                    completion(.failure(error))
                    return
                }
                // Read response
                self?.recvFrame(connection: connection) { result in
                    switch result {
                    case .failure(let error):
                        completion(.failure(error))
                    case .success(let respData):
                        guard let resp = try? JSONSerialization.jsonObject(with: respData) as? [String: Any],
                              resp["ok"] as? Bool == true else {
                            let err = (try? JSONSerialization.jsonObject(with: respData) as? [String: Any])?["err"] as? String ?? "unknown"
                            completion(.failure(XzapError.handshakeFailed(err)))
                            return
                        }
                        let tunnel = TunnelConnection(connection: connection, tunnel: self!)
                        completion(.success(tunnel))
                    }
                }
            }
        } catch {
            completion(.failure(error))
        }
    }

    // MARK: - Frame I/O

    func buildFrame(_ data: Data) throws -> Data {
        let encrypted = try crypto.encrypt(data)
        var prefix = Data(count: Self.prefixSize)
        prefix.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, Self.prefixSize, $0.baseAddress!) }
        let payload = prefix + encrypted
        var frame = Data()
        frame.append(contentsOf: withUnsafeBytes(of: UInt32(payload.count).bigEndian) { Array($0) })
        frame.append(payload)
        return frame
    }

    func sendFragmented(connection: NWConnection, data: Data,
                        completion: @escaping (Error?) -> Void) {
        let fragged: Data
        if data.count <= Self.fragThreshold {
            fragged = microFragment(data)
        } else {
            fragged = packFragment(data: data, flags: 0x00)
        }
        connection.send(content: fragged, completion: .contentProcessed { error in
            completion(error)
        })
    }

    func recvFrame(connection: NWConnection,
                   completion: @escaping (Result<Data, Error>) -> Void) {
        // Read fragmentation header [4B total][1B flags]
        recvFragmentedFrame(connection: connection, buffer: Data()) { [weak self] result in
            switch result {
            case .failure(let error):
                completion(.failure(error))
            case .success(let frameData):
                guard frameData.count >= 4 else {
                    completion(.failure(XzapError.connectionClosed))
                    return
                }
                let length = Int(UInt32(bigEndian: frameData.prefix(4).withUnsafeBytes { $0.load(as: UInt32.self) }))
                guard length <= Self.maxFrame, frameData.count >= 4 + length else {
                    completion(.failure(XzapError.frameTooLarge))
                    return
                }
                let payload = frameData[4..<(4 + length)]
                let encrypted = payload.dropFirst(Self.prefixSize)
                do {
                    let decrypted = try self?.crypto.decrypt(Data(encrypted))
                    completion(.success(decrypted ?? Data()))
                } catch {
                    completion(.failure(error))
                }
            }
        }
    }

    // MARK: - Fragmentation

    private func microFragment(_ data: Data) -> Data {
        var result = Data()
        var offset = 0
        while offset < data.count {
            let remaining = data.count - offset
            let fragSize: Int
            if remaining <= Self.fragMax {
                fragSize = remaining
            } else {
                fragSize = Int.random(in: Self.fragMin...min(Self.fragMax, remaining))
            }
            let chunk = data[offset..<(offset + fragSize)]
            result.append(packFragment(data: Data(chunk), flags: 0x00))
            offset += fragSize
        }
        return result
    }

    private func packFragment(data: Data, flags: UInt8) -> Data {
        let total = UInt32(data.count + 1)
        var frag = Data()
        frag.append(contentsOf: withUnsafeBytes(of: total.bigEndian) { Array($0) })
        frag.append(flags)
        frag.append(data)
        return frag
    }

    private func recvFragmentedFrame(connection: NWConnection, buffer: Data,
                                      completion: @escaping (Result<Data, Error>) -> Void) {
        // Read [4B total]
        connection.receive(minimumIncompleteLength: 4, maximumLength: 65536) { [weak self] content, _, isComplete, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            guard let content = content, !content.isEmpty else {
                if isComplete {
                    completion(.failure(XzapError.connectionClosed))
                } else {
                    // Retry
                    self?.recvFragmentedFrame(connection: connection, buffer: buffer, completion: completion)
                }
                return
            }

            var all = buffer + content

            // Parse fragmentation frames from buffer
            while all.count >= 5 { // 4B total + 1B flags minimum
                let total = Int(UInt32(bigEndian: all.prefix(4).withUnsafeBytes { $0.load(as: UInt32.self) }))
                guard total > 0 else {
                    completion(.failure(XzapError.connectionClosed))
                    return
                }
                guard all.count >= 4 + total else {
                    // Need more data
                    connection.receive(minimumIncompleteLength: 4 + total - all.count, maximumLength: 65536) { more, _, _, err in
                        if let err = err {
                            completion(.failure(err))
                            return
                        }
                        if let more = more {
                            self?.recvFragmentedFrame(connection: connection, buffer: all + more, completion: completion)
                        }
                    }
                    return
                }

                let flags = all[4]
                let fragData = all[5..<(4 + total)]
                all = Data(all.dropFirst(4 + total))

                if flags == 0x01 { continue } // chaff

                // Got real data — check if we have complete XZAP frame
                if fragData.count >= 4 {
                    let xzapLen = Int(UInt32(bigEndian: Data(fragData.prefix(4)).withUnsafeBytes { $0.load(as: UInt32.self) }))
                    if fragData.count >= 4 + xzapLen {
                        completion(.success(Data(fragData)))
                        return
                    }
                    // Need more fragments — accumulate
                    var accumulated = Data(fragData)
                    self?.recvMoreFragments(connection: connection, buffer: all,
                                            accumulated: &accumulated, needed: 4 + xzapLen,
                                            completion: completion)
                    return
                }
            }

            // Not enough data yet, read more
            self?.recvFragmentedFrame(connection: connection, buffer: all, completion: completion)
        }
    }

    private func recvMoreFragments(connection: NWConnection, buffer: Data,
                                    accumulated: inout Data, needed: Int,
                                    completion: @escaping (Result<Data, Error>) -> Void) {
        if accumulated.count >= needed {
            completion(.success(accumulated))
            return
        }
        var acc = accumulated
        connection.receive(minimumIncompleteLength: 5, maximumLength: 65536) { [weak self] content, _, _, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            guard let content = content else {
                completion(.failure(XzapError.connectionClosed))
                return
            }
            var data = buffer + content
            // Parse next fragment
            guard data.count >= 5 else {
                self?.recvMoreFragments(connection: connection, buffer: data,
                                        accumulated: &acc, needed: needed, completion: completion)
                return
            }
            let total = Int(UInt32(bigEndian: data.prefix(4).withUnsafeBytes { $0.load(as: UInt32.self) }))
            guard data.count >= 4 + total else { return }
            let flags = data[4]
            let fragData = data[5..<(4 + total)]
            data = Data(data.dropFirst(4 + total))
            if flags != 0x01 {
                acc.append(Data(fragData))
            }
            if acc.count >= needed {
                completion(.success(acc))
            } else {
                self?.recvMoreFragments(connection: connection, buffer: data,
                                        accumulated: &acc, needed: needed, completion: completion)
            }
        }
    }
}


/// Active tunnel connection.
class TunnelConnection {
    let connection: NWConnection
    let tunnel: XzapTunnel

    init(connection: NWConnection, tunnel: XzapTunnel) {
        self.connection = connection
        self.tunnel = tunnel
    }

    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        do {
            let frame = try tunnel.buildFrame(data)
            tunnel.sendFragmented(connection: connection, data: frame, completion: completion)
        } catch {
            completion(error)
        }
    }

    func receive(completion: @escaping (Result<Data, Error>) -> Void) {
        tunnel.recvFrame(connection: connection, completion: completion)
    }

    func close() {
        connection.cancel()
    }
}
