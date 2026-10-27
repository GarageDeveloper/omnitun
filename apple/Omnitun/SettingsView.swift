// Settings (mockup E15). VPNs are managed in their own window.

import ServiceManagement
import SwiftUI
import VPNClientCore

struct SettingsView: View {
    enum Tab: Hashable { case general, service, about }

    @ObservedObject var model: AppModel
    @State var tab: Tab

    var body: some View {
        TabView(selection: $tab) {
            GeneralSettings().tabItem { Label("General", systemImage: "gearshape") }.tag(Tab.general)
            ServiceSettings(model: model).tabItem { Label("Service", systemImage: "server.rack") }.tag(Tab.service)
            AboutView().tabItem { Label("About", systemImage: "info.circle") }.tag(Tab.about)
        }
        .padding(20)
        // A fixed size: grouped forms have no height of their own, and the
        // first tab would open collapsed.
        .frame(width: 560, height: 520)
    }
}

/// Name, version, copyright and licence: free software, MIT or Apache 2.0.
private struct AboutView: View {
    private var version: String {
        let info = Bundle.main.infoDictionary ?? [:]
        let short = info["CFBundleShortVersionString"] as? String ?? "–"
        let details = [info["CFBundleVersion"], info["BuildCommit"]].compactMap { $0 as? String }
        return details.isEmpty ? short : "\(short) (\(details.joined(separator: ", ")))"
    }

    var body: some View {
        VStack(spacing: 12) {
            Image(nsImage: NSApp.applicationIconImage).resizable().frame(width: 96, height: 96)
            Text(verbatim: brand.product).font(.title.bold())
            Text(String(localized: "Version \(version)")).foregroundStyle(.secondary).textSelection(.enabled)
            Text("A VPN client for FortiGate SSL VPN, IPsec, OpenVPN and L2TP, several at a time.")
                .multilineTextAlignment(.center)
            Divider().frame(width: 300)
            Text(verbatim: "© 2026 GarageDeveloper and the \(brand.product) contributors")
            Text("Free software: use, change and share it under the MIT license or the Apache License 2.0, as you prefer.")
                .font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
            HStack {
                Link("MIT License", destination: URL(string: "https://opensource.org/license/mit")!)
                Text(verbatim: "·").foregroundStyle(.secondary)
                Link("Apache License 2.0", destination: URL(string: "https://www.apache.org/licenses/LICENSE-2.0")!)
            }
            .font(.callout)
            if let notices = Bundle.main.url(forResource: "ThirdPartyNotices", withExtension: "txt") {
                Button("Third-Party Licenses…") { NSWorkspace.shared.open(notices) }
                    .buttonStyle(.link).font(.callout)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }
}

private struct GeneralSettings: View {
    @State private var openAtLogin = LoginItem.isEnabled
    @State private var disconnectOnQuit = Settings.disconnectOnQuit
    @State private var notifyConnected = Settings.notifyConnected
    @State private var notifyFailures = Settings.notifyFailures
    @State private var language = Settings.language
    @State private var checkUpdates = Updates.shared.checksAutomatically
    private let startedWith = Settings.language

    var body: some View {
        Form {
            Section("General") {
                Toggle("Open \(brand.product) at login", isOn: $openAtLogin)
                    .onChange(of: openAtLogin) { _, on in
                        do { try LoginItem.set(on) } catch { openAtLogin = LoginItem.isEnabled }
                    }
                Toggle("Disconnect VPNs when I quit \(brand.product)", isOn: $disconnectOnQuit)
                    .onChange(of: disconnectOnQuit) { _, on in Settings.disconnectOnQuit = on }
                Text("Without the app, a code or a browser login cannot be asked again when a VPN reconnects.")
                    .font(.caption).foregroundStyle(.secondary)
                if Updates.shared.available {
                    Toggle("Check for updates every day", isOn: $checkUpdates)
                        .onChange(of: checkUpdates) { _, on in Updates.shared.checksAutomatically = on }
                    Button("Check for Updates Now") { Updates.shared.checkNow() }
                }
            }
            Section("Language") {
                Picker("Language", selection: $language) {
                    Text("Same as macOS").tag(Settings.Language.system)
                    Text(verbatim: "English").tag(Settings.Language.english)
                    Text(verbatim: "Français").tag(Settings.Language.french)
                }
                .onChange(of: language) { _, value in Settings.language = value }
                if language != startedWith {
                    HStack {
                        Text("Takes effect when \(brand.product) restarts; your VPNs stay connected.")
                            .font(.caption).foregroundStyle(.secondary)
                        Spacer()
                        Button("Restart Now") { relaunch() }
                    }
                }
            }
            Section("Notifications") {
                Toggle("Connected", isOn: $notifyConnected)
                    .onChange(of: notifyConnected) { _, on in Settings.notifyConnected = on }
                Toggle("Unexpected disconnection or failure (recommended)", isOn: $notifyFailures)
                    .onChange(of: notifyFailures) { _, on in Settings.notifyFailures = on }
                Text("Security alerts (changed certificate) are always shown.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
    }
}

private struct ServiceSettings: View {
    @ObservedObject var model: AppModel

    var body: some View {
        Form {
            Section("VPN Service") {
                switch model.service {
                case .checking:
                    Text("Checking…")
                case let .running(info):
                    Label("Running · version \(info.version) · \(model.sessions.count) session(s)", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                case let .unavailable(reason):
                    Label(reason, systemImage: "xmark.circle.fill").foregroundStyle(.red)
                }
                HStack {
                    Button("Restart the Service") { model.restartService() }
                        .disabled({ if case .running = model.service { false } else { true } }())
                    Button("Open System Settings…") { SMAppService.openSystemSettingsLoginItems() }
                    Button("Check") { model.refreshService() }
                }
                Text("Restarting the service disconnects every VPN.").font(.caption).foregroundStyle(.secondary)
            }
            Section("Diagnostic") {
                Button("Create Diagnostic Report…") { createReport() }
                    .disabled(creating)
                Text("A text file to send when something goes wrong: versions, VPNs and their sessions, the service's log of the last day. No password, key or certificate; servers, accounts, domains and addresses are replaced. Read it before sending it.")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
        .formStyle(.grouped)
    }

    @State private var creating = false

    private func createReport() {
        creating = true
        let info = Bundle.main.infoDictionary ?? [:]
        let details = [info["CFBundleVersion"], info["BuildCommit"]].compactMap { $0 as? String }.joined(separator: ", ")
        let client = "\(brand.product) \(info["CFBundleShortVersionString"] as? String ?? "") (\(details))"
        Task {
            let report = await model.client.diagnosticReport(client: client)
            creating = false
            let panel = NSSavePanel()
            let stamp = Date().formatted(.iso8601.year().month().day().dateSeparator(.dash))
            panel.nameFieldStringValue = "\(brand.product) diagnostic \(stamp).txt"
            panel.allowedContentTypes = [.plainText]
            NSApp.activate()
            guard panel.runModal() == .OK, let url = panel.url else { return }
            do {
                try report.write(to: url, atomically: true, encoding: .utf8)
                NSWorkspace.shared.activateFileViewerSelecting([url])
            } catch {
                Windows.shared.alert(String(localized: "The report could not be saved"), describe(error))
            }
        }
    }
}

// Its own `id` field: the profile's stable id.
extension ProfileSummary: Identifiable {}
