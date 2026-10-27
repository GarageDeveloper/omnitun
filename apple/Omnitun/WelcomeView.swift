// Welcome (mockup E10): checks that the system service is there and
// answers; offers notifications and opening at login.

import ServiceManagement
import SwiftUI
import UserNotifications
import VPNClientCore

/// The LaunchDaemon installed by the package.
enum ServiceInstall {
    static var plist: String { "/Library/LaunchDaemons/\(brand.launchdLabel).plist" }

    /// Installed by the package, so owned by root: a user-writable plist
    /// would let any program of the session run code as root.
    static var isInstalled: Bool {
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: plist) else { return false }
        return (attributes[.ownerAccountID] as? NSNumber)?.intValue == 0
    }
}

enum LoginItem {
    static var isEnabled: Bool { SMAppService.mainApp.status == .enabled }

    static func set(_ on: Bool) throws {
        if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
    }
}

struct CheckRow<Accessory: View>: View {
    let ok: Bool?
    let title: String
    let detail: String
    @ViewBuilder var accessory: Accessory

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Group {
                switch ok {
                case .some(true): Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                case .some(false): Image(systemName: "xmark.circle.fill").foregroundStyle(.red)
                case .none: ProgressView().controlSize(.small)
                }
            }
            .font(.title3)
            .frame(width: 22)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                Text(detail).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            accessory
        }
    }
}

struct WelcomeView: View {
    @ObservedObject var model: AppModel
    @State private var installed = ServiceInstall.isInstalled
    @State private var notifications: UNAuthorizationStatus?
    @State private var openAtLogin = LoginItem.isEnabled

    private var running: Bool? {
        switch model.service {
        case .checking: nil
        case .running: true
        case .unavailable: false
        }
    }

    private var serviceDetail: String {
        switch model.service {
        case .checking: String(localized: "Checking…")
        case let .running(info): String(localized: "Version \(info.version) · protocol \(info.protocol)")
        case let .unavailable(reason): reason
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Is everything ready on your side?").font(.title2.bold())
                Text("\(brand.product) checks that its system service works. There is nothing to do if everything is ticked.")
                    .foregroundStyle(.secondary)
            }
            VStack(alignment: .leading, spacing: 14) {
                CheckRow(ok: installed, title: String(localized: "VPN service installed"),
                         detail: installed ? String(localized: "Installed by the package, write-protected (root)")
                                           : String(localized: "Install \(brand.product) with its .pkg package.")) { EmptyView() }
                CheckRow(ok: running, title: String(localized: "Service running and compatible"), detail: serviceDetail) {
                    if running == false { Button("Try Again") { model.refreshService() } }
                }
                if running == false && installed {
                    Text("If the service was turned off in System Settings, turn \(brand.product) back on in Login Items & Extensions › Allow in the Background.")
                        .font(.caption)
                        .fixedSize(horizontal: false, vertical: true)
                    Button("Open System Settings") { SMAppService.openSystemSettingsLoginItems() }
                }
                CheckRow(ok: notifications.map { $0 == .authorized || $0 == .provisional },
                         title: String(localized: "Notifications"),
                         detail: String(localized: "To be told about a dropped VPN or a code request")) {
                    if notifications == .notDetermined {
                        Button("Allow…") {
                            Task {
                                await Notifier.shared.requestAuthorization()
                                notifications = await Notifier.shared.status()
                            }
                        }
                    }
                }
                Toggle(isOn: $openAtLogin) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Open \(brand.product) at login")
                        Text("You can change this later in Settings").font(.caption).foregroundStyle(.secondary)
                    }
                }
                .onChange(of: openAtLogin) { _, on in
                    do { try LoginItem.set(on) } catch { openAtLogin = LoginItem.isEnabled }
                }
            }
            HStack {
                Spacer()
                Button("Continue") {
                    Settings.welcomed = true
                    Windows.shared.close("welcome")
                    // No VPN yet: offer those of the other apps.
                    if model.profiles.isEmpty && model.profilesError == nil && !Settings.offeredImport {
                        Windows.shared.showSetup(model: model)
                    }
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(24)
        .frame(width: 480)
        .task {
            model.refreshService()
            notifications = await Notifier.shared.status()
        }
    }
}
