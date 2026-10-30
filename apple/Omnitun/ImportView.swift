// Import from FortiClient, Viscosity or macOS (mockup E11, simple version): the
// detected profiles, which to add, and what is left to do. Their secrets
// cannot be read: the pre-shared key or password can be typed here, the
// rest is asked at the first connection.

import SwiftUI
import VPNClientCore

/// Where an import reads the profiles of another VPN client.
enum ImportSource {
    case fortiClient, viscosity, openVpnConnect, macOS

    /// The import window's key.
    var window: String {
        switch self {
        case .fortiClient: "import"
        case .viscosity: "import-viscosity"
        case .openVpnConnect: "import-openvpn-connect"
        case .macOS: "import-macos"
        }
    }

    var title: LocalizedStringKey {
        switch self {
        case .fortiClient: "FortiClient Profiles Found"
        case .viscosity: "Viscosity Connections Found"
        case .openVpnConnect: "OpenVPN Connect Profiles Found"
        case .macOS: "macOS VPNs Found"
        }
    }

    var empty: LocalizedStringKey {
        switch self {
        case .fortiClient: "No FortiClient profile on this Mac."
        case .viscosity: "No Viscosity connection on this Mac."
        case .openVpnConnect: "No OpenVPN Connect profile on this Mac."
        case .macOS: "No VPN in System Settings that can be imported."
        }
    }

    var secrets: LocalizedStringKey {
        switch self {
        case .fortiClient:
            "FortiClient's passwords and pre-shared keys cannot be read. A pre-shared key typed here is saved in the Keychain; the others are asked at the first connection."
        case .viscosity:
            "Viscosity's passwords stay in its own Keychain items. A password typed here is saved in the Keychain; otherwise it is asked at the first connection."
        case .openVpnConnect:
            "OpenVPN Connect's passwords stay in its own Keychain items. A password typed here is saved in the Keychain; otherwise it is asked at the first connection."
        case .macOS:
            "The shared secrets and passwords of System Settings stay in the System keychain. Those typed here are saved in your Keychain; the others are asked at the first connection."
        }
    }
}

/// A profile found by an import, with where it comes from: the same name
/// can come from two sources.
private struct Found: Identifiable {
    let source: ImportSource
    let profile: ImportedProfile
    var id: String { "\(source.window)/\(profile.name)" }
}

struct ImportView: View {
    @ObservedObject var model: AppModel
    var sources: [ImportSource] = [.fortiClient]
    /// The first-launch assistant: every source at once, the sources with
    /// nothing hidden, and the other ways to add a VPN.
    var setup = false
    @State private var found: [Found] = []
    /// By `Found.id`.
    @State private var chosen: Set<String> = []
    /// Secrets typed for the chosen profiles, by `Found.id` then key
    /// ("psk", "password").
    @State private var secrets: [String: [String: String]] = [:]
    /// By source; one source failing does not hide the others.
    @State private var errors: [ImportSource: String] = [:]
    @State private var loaded = false
    /// The sections' height: the list takes it, within bounds, so that the
    /// window grows with what `load` finds.
    @State private var listHeight: CGFloat = 0

    private var known: Set<String> { Set(model.profiles.map(\.name)) }
    private var window: String { setup ? Windows.setupKey : sources[0].window }
    /// The sources worth a section.
    private var shown: [ImportSource] {
        sources.filter { source in !setup || errors[source] == nil && found.contains { $0.source == source } }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            if setup {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Bring Your VPNs").font(.title2.bold())
                    Text(found.isEmpty && loaded
                         ? "No other VPN app was found on this Mac. Import a configuration file, or create a VPN with the details from your IT department."
                         : "\(brand.product) found VPNs set up in other apps on this Mac. Choose those to add: the other apps keep theirs.")
                        .foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
            }
            if !shown.isEmpty {
                ScrollView {
                    VStack(alignment: .leading, spacing: 16) {
                        ForEach(shown, id: \.self) { source in section(source) }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .onGeometryChange(for: CGFloat.self, of: { $0.size.height }) { listHeight = $0 }
                }
                .frame(height: min(max(listHeight, 120), setup ? 420 : 320))
            }
            HStack {
                if setup {
                    Button("Import a File…") { Windows.shared.importOpenVpn(model: model) }
                    Button("Create a VPN…") {
                        Windows.shared.close(window)
                        Windows.shared.showManage(model: model)
                    }
                }
                Spacer()
                Button(setup ? "Not Now" : "Close") { Windows.shared.close(window) }.keyboardShortcut(.cancelAction)
                if !found.isEmpty || !setup {
                    Button("Add \(chosen.count) Profile(s)") { add() }
                        .keyboardShortcut(.defaultAction)
                        .disabled(chosen.isEmpty)
                }
            }
        }
        .padding(20)
        .frame(width: setup ? 560 : 520)
        .onAppear(perform: load)
    }

    @ViewBuilder
    private func section(_ source: ImportSource) -> some View {
        let items = found.filter { $0.source == source }
        VStack(alignment: .leading, spacing: 12) {
            Text(source.title).font(setup ? .headline : .title3.bold())
            if let error = errors[source] {
                Text(error).foregroundStyle(.secondary)
            } else if items.isEmpty {
                Text(source.empty).foregroundStyle(.secondary)
            }
            ForEach(items) { item in row(item) }
            if !items.isEmpty {
                Text(source.secrets)
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    @ViewBuilder
    private func row(_ item: Found) -> some View {
        let profile = item.profile
        let exists = known.contains(profile.name)
        Toggle(isOn: binding(item)) {
            VStack(alignment: .leading, spacing: 2) {
                Text(profile.name).bold()
                if let refused = profile.refused {
                    Text("Cannot be imported: \(refused)").font(.caption).foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                } else if exists {
                    Text("Already added").font(.caption).foregroundStyle(.secondary)
                } else if let other = profile.duplicateOf {
                    Text("Same server as \(other), already added").font(.caption).foregroundStyle(.secondary)
                }
                ForEach(profile.notes, id: \.self) { note in
                    Text(note).font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .disabled(exists || profile.refused != nil)
        if chosen.contains(item.id) && (profile.needsPsk || profile.needsPassword) {
            Grid(alignment: .leading, horizontalSpacing: 8, verticalSpacing: 6) {
                if profile.needsPsk {
                    SecretRow(label: "Pre-shared key (VPN)", text: secret(item.id, "psk"))
                }
                if profile.needsPassword {
                    SecretRow(label: "User password", text: secret(item.id, "password"))
                }
            }
            .padding(.leading, 20)
        }
    }

    /// Two VPNs of the same name cannot both be added: choosing one
    /// leaves out the other.
    private func binding(_ item: Found) -> Binding<Bool> {
        Binding(get: { chosen.contains(item.id) }, set: { on in
            if on {
                for other in found where other.profile.name == item.profile.name { chosen.remove(other.id) }
                chosen.insert(item.id)
            } else {
                chosen.remove(item.id)
            }
        })
    }

    private func secret(_ id: String, _ key: String) -> Binding<String> {
        Binding(get: { secrets[id]?[key] ?? "" }, set: { secrets[id, default: [:]][key] = $0 })
    }

    private func load() {
        model.reloadProfiles()
        found = []
        errors = [:]
        for source in sources {
            do {
                let profiles = switch source {
                case .fortiClient: try model.client.importForticlient(path: nil)
                case .viscosity: try model.client.importViscosity(path: nil)
                case .openVpnConnect: try model.client.importOpenvpnConnect(path: nil)
                case .macOS: try model.client.importMacos(path: nil)
                }
                found += profiles.map { Found(source: source, profile: $0) }
            } catch {
                errors[source] = describe(error)
            }
        }
        // The first of each name not added yet, unless its server is: it
        // may be the same VPN under another name.
        var names = known
        chosen = Set(found.filter {
            $0.profile.refused == nil && $0.profile.duplicateOf == nil && names.insert($0.profile.name).inserted
        }.map(\.id))
        loaded = true
    }

    private func add() {
        let picked = found.filter { chosen.contains($0.id) }
        let toml = picked.map(\.profile.toml).joined(separator: "\n")
        do {
            // The new profiles' ids, in the order of their tables.
            let added = try model.client.addProfiles(toml: toml)
            model.reloadProfiles()
            defer {
                model.secretsDidChange()
                model.imported = added
            }
            for (id, item) in zip(added, picked) {
                for (key, value) in secrets[item.id] ?? [:] {
                    let value = value.trimmingCharacters(in: .whitespacesAndNewlines)
                    if !value.isEmpty { try model.client.setSecret(id: id, key: key, value: value) }
                }
            }
            secrets = [:]
            chosen = []
            Windows.shared.close(window)
            Notifier.shared.post(title: String(localized: "\(added.count) profile(s) imported"),
                                 body: picked.map(\.profile.name).joined(separator: ", "))
            if setup { Windows.shared.showManage(model: model, profile: added.first) }
        } catch {
            errors[picked.first?.source ?? sources[0]] = describe(error)
        }
    }
}

/// An OpenVPN file the user picked, converted by VPNClientCore: what the
/// import left out, the password to save if the server asks for one, then
/// the profile is added.
/// Or a WireGuard file: then added from `wireGuard`, its keys going
/// straight to the Keychain.
struct OpenVpnImportView: View {
    @ObservedObject var model: AppModel
    let fileName: String
    let imported: ImportedProfile
    var wireGuard: URL?
    let close: () -> Void
    @State private var password = ""
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "doc.badge.plus").font(.system(size: 28)).foregroundStyle(.tint).frame(width: 36)
                VStack(alignment: .leading, spacing: 2) {
                    Text(wireGuard == nil ? "Add a VPN from an OpenVPN file" : "Add a VPN from a WireGuard file")
                        .font(.headline)
                    Text(verbatim: fileName).font(.callout).foregroundStyle(.secondary)
                }
            }
            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 6) {
                GridRow {
                    Text("Name").foregroundStyle(.secondary)
                    Text(verbatim: imported.name).bold()
                }
            }
            if !imported.notes.isEmpty {
                ScrollView {
                    VStack(alignment: .leading, spacing: 6) {
                        ForEach(imported.notes, id: \.self) { note in
                            Label {
                                Text(verbatim: note).fixedSize(horizontal: false, vertical: true)
                            } icon: {
                                Image(systemName: "info.circle").foregroundStyle(.secondary)
                            }
                            .font(.caption)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: 200)
            }
            if imported.needsPassword {
                Grid(alignment: .leading, horizontalSpacing: 8) {
                    SecretRow(label: "User password", text: $password)
                }
            }
            Text(wireGuard == nil
                 ? "Passwords are never imported. The certificates and keys of the file are copied into the profile: the file is no longer needed."
                 : "The keys of the file go to the Keychain, the rest into the profile: the file is no longer needed. Its commands (PostUp…) are never run.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                Button("Cancel", action: close).keyboardShortcut(.cancelAction)
                Button("Add") { add(connect: false) }
                Button("Add and Connect") { add(connect: true) }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 520)
    }

    private func add(connect: Bool) {
        do {
            let added = try wireGuard.map { [try model.client.addWireguard(path: $0.path)] }
                ?? model.client.addProfiles(toml: imported.toml)
            model.reloadProfiles()
            defer {
                model.secretsDidChange()
                model.imported = added
            }
            if let id = added.first, !password.isEmpty {
                try model.client.setSecret(id: id, key: "password", value: password)
            }
            password = ""
            close()
            if connect, let id = added.first { model.connect(id) }
        } catch {
            self.error = describe(error)
        }
    }
}

/// A secret typed at import, with its name shown: outside a form, a
/// secure field shows no label.
private struct SecretRow: View {
    let label: LocalizedStringKey
    @Binding var text: String

    var body: some View {
        GridRow {
            Text(label).foregroundStyle(.secondary).gridColumnAlignment(.trailing)
            SecureField("", text: $text, prompt: Text("Optional: asked at the first connection otherwise"))
                .labelsHidden()
        }
    }
}
