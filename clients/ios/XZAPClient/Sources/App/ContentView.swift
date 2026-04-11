import SwiftUI
import NetworkExtension

struct ContentView: View {
    @State private var server = ""
    @State private var port = "8443"
    @State private var key = ""
    @State private var useTLS = true
    @State private var connected = false
    @State private var status = "Disconnected"
    @State private var statusColor = Color.red

    var body: some View {
        NavigationView {
            Form {
                Section("Server") {
                    TextField("Host", text: $server)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                    TextField("Port", text: $port)
                        .keyboardType(.numberPad)
                    SecureField("Key (base64)", text: $key)
                    Toggle("TLS (anti-DPI)", isOn: $useTLS)
                }

                Section {
                    Button(action: toggleConnection) {
                        HStack {
                            Image(systemName: connected ? "lock.fill" : "lock.open")
                            Text(connected ? "Disconnect" : "Connect")
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(connected ? .red : .blue)
                    .disabled(server.isEmpty || key.isEmpty)
                }

                Section("Status") {
                    HStack {
                        Circle()
                            .fill(statusColor)
                            .frame(width: 10, height: 10)
                        Text(status)
                    }
                }
            }
            .navigationTitle("XZAP")
        }
        .onAppear(perform: loadSettings)
    }

    private func toggleConnection() {
        if connected {
            disconnect()
        } else {
            connect()
        }
    }

    private func connect() {
        saveSettings()
        status = "Connecting..."
        statusColor = .yellow

        let manager = NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = "com.xzap.client.tunnel"
        proto.serverAddress = server
        proto.providerConfiguration = [
            "server": server,
            "port": Int(port) ?? 8443,
            "key": key,
            "tls": useTLS,
        ]
        manager.protocolConfiguration = proto
        manager.localizedDescription = "XZAP"
        manager.isEnabled = true

        manager.saveToPreferences { error in
            if let error = error {
                status = "Error: \(error.localizedDescription)"
                statusColor = .red
                return
            }

            manager.loadFromPreferences { error in
                if let error = error {
                    status = "Error: \(error.localizedDescription)"
                    statusColor = .red
                    return
                }

                do {
                    try (manager.connection as? NETunnelProviderSession)?.startTunnel()
                    connected = true
                    status = "Connected to \(server)"
                    statusColor = .green
                } catch {
                    status = "Error: \(error.localizedDescription)"
                    statusColor = .red
                }
            }
        }
    }

    private func disconnect() {
        let manager = NETunnelProviderManager()
        manager.connection.stopVPNTunnel()
        connected = false
        status = "Disconnected"
        statusColor = .red
    }

    private func saveSettings() {
        UserDefaults.standard.set(server, forKey: "server")
        UserDefaults.standard.set(port, forKey: "port")
        UserDefaults.standard.set(key, forKey: "key")
        UserDefaults.standard.set(useTLS, forKey: "tls")
    }

    private func loadSettings() {
        server = UserDefaults.standard.string(forKey: "server") ?? ""
        port = UserDefaults.standard.string(forKey: "port") ?? "8443"
        key = UserDefaults.standard.string(forKey: "key") ?? ""
        useTLS = UserDefaults.standard.bool(forKey: "tls")
    }
}
