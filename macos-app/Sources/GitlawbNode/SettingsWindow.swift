import AppKit
import SwiftUI

/// Hosts the SwiftUI settings view in an NSWindow.
class SettingsWindowController: NSWindowController {
    convenience init() {
        let hostingController = NSHostingController(rootView: SettingsView())
        let window = NSWindow(contentViewController: hostingController)
        window.title = "Gitlawb Node Settings"
        window.setContentSize(NSSize(width: 480, height: 280))
        window.styleMask = [.titled, .closable, .miniaturizable]
        window.center()
        self.init(window: window)
    }
}

struct SettingsView: View {
    @State private var httpPort: String = String(Config.shared.httpPort)
    @State private var p2pPort: String = String(Config.shared.p2pPort)
    @State private var publicURL: String = Config.shared.publicURL
    @State private var postgresPassword: String = Config.shared.postgresPassword
    @State private var autoStartOnLaunch: Bool = Config.shared.autoStartOnLaunch

    // Advanced (collapsed by default)
    @State private var showAdvanced: Bool = false
    @State private var chainRpcURL: String = Config.shared.chainRpcURL
    @State private var contractNodeStaking: String = Config.shared.contractNodeStaking
    @State private var operatorPrivateKey: String = Config.shared.operatorPrivateKey
    @State private var tigrisBucket: String = Config.shared.tigrisBucket
    @State private var autoSync: Bool = Config.shared.autoSync

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("General")
                .font(.headline)

            Form {
                TextField("HTTP Port:", text: $httpPort)
                    .textFieldStyle(.roundedBorder)
                TextField("P2P Port:", text: $p2pPort)
                    .textFieldStyle(.roundedBorder)
                TextField("Public URL:", text: $publicURL)
                    .textFieldStyle(.roundedBorder)
                SecureField("Postgres Password:", text: $postgresPassword)
                    .textFieldStyle(.roundedBorder)
            }
            .formStyle(.columns)

            Toggle("Auto-start node on app launch", isOn: $autoStartOnLaunch)
            VStack(alignment: .leading, spacing: 2) {
                Toggle("Sync repos from peers", isOn: $autoSync)
                Text("Automatically replicate repositories from other nodes in the network")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Divider()

            DisclosureGroup("Advanced (Operator & Storage)", isExpanded: $showAdvanced) {
                Form {
                    TextField("Chain RPC URL:", text: $chainRpcURL)
                        .textFieldStyle(.roundedBorder)
                    TextField("Staking Contract:", text: $contractNodeStaking)
                        .textFieldStyle(.roundedBorder)
                    SecureField("Operator Private Key:", text: $operatorPrivateKey)
                        .textFieldStyle(.roundedBorder)
                    TextField("Tigris Bucket:", text: $tigrisBucket)
                        .textFieldStyle(.roundedBorder)
                }
                .formStyle(.columns)
                .padding(.top, 4)
            }

            HStack {
                Spacer()
                Button("Save") {
                    save()
                }
                .keyboardShortcut(.defaultAction)
            }
            .padding(.top, 8)
        }
        .padding(20)
        .fixedSize(horizontal: false, vertical: true)
        .frame(width: 440)
    }

    private func save() {
        Config.shared.httpPort = Int(httpPort) ?? 7545
        Config.shared.p2pPort = Int(p2pPort) ?? 7546
        Config.shared.publicURL = publicURL
        Config.shared.postgresPassword = postgresPassword
        Config.shared.autoStartOnLaunch = autoStartOnLaunch
        Config.shared.chainRpcURL = chainRpcURL
        Config.shared.contractNodeStaking = contractNodeStaking
        Config.shared.operatorPrivateKey = operatorPrivateKey
        Config.shared.tigrisBucket = tigrisBucket
        Config.shared.autoSync = autoSync

        Config.shared.persist()
        Config.shared.writeEnvFile()

        // Close the window
        NSApp.keyWindow?.close()
    }
}
