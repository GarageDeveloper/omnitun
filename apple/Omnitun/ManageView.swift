// "Manage VPNs" (mockups E6, E13, E14): the list, the editor, creation by
// type, deletion and export. Profiles are saved through VPNClientCore,
// which keeps the user's file as it was apart from the edited values.

import Combine
import SwiftUI
import UniformTypeIdentifiers
import VPNClientCore

/// The editing state of the Manage VPNs window. It outlives the view so
/// that the window can ask about unsaved changes before closing.
@MainActor
final class ProfileEditing: ObservableObject {
    let model: AppModel
    /// The id of the profile shown in the editor (nil while creating one).
    @Published private(set) var selection: String?
    @Published var form: ProfileForm?
    /// The form as last loaded or saved: edits are the difference.
    @Published private(set) var saved: ProfileForm?
    /// The profile's name before editing (nil: new).
    @Published private(set) var original: String?
    @Published var error: String?
    /// Secrets typed in the editor ("psk", "password"), stored in the
    /// Keychain when the profile is saved; never read back.
    @Published var typedSecrets: [String: String] = [:]
    /// Secrets to remove from the Keychain when the profile is saved.
    @Published var forgotten: Set<String> = []
    /// Secrets the Keychain holds for the profile.
    @Published private(set) var storedSecrets: Set<String> = []

    private var subscriptions: Set<AnyCancellable> = []

    init(model: AppModel) {
        self.model = model
        // Secrets saved elsewhere (a connection, an import) show at once.
        model.$secretsChanged.dropFirst().receive(on: DispatchQueue.main)
            .sink { [weak self] _ in self?.refreshStoredSecrets() }
            .store(in: &subscriptions)
        // An import selects what it added.
        model.$imported.dropFirst().filter { !$0.isEmpty }.receive(on: DispatchQueue.main)
            .sink { [weak self] ids in
                guard let self, let first = ids.first else { return }
                self.leave { self.select(first) }
            }
            .store(in: &subscriptions)
    }

    var isNew: Bool { form != nil && original == nil }
    var hasChanges: Bool {
        form != nil && (isNew || form != saved || typedSecrets.values.contains { !$0.isEmpty } || !forgotten.isEmpty)
    }

    /// A secret field of the editor: empty means "leave as it is".
    func secret(_ key: String) -> Binding<String> {
        Binding(get: { self.typedSecrets[key] ?? "" }, set: {
            self.typedSecrets[key] = $0
            if !$0.isEmpty { self.forgotten.remove(key) }
        })
    }

    func isStored(_ key: String) -> Bool { storedSecrets.contains(key) && !forgotten.contains(key) }

    func forget(_ key: String) {
        typedSecrets[key] = nil
        forgotten.insert(key)
    }

    private func clearSecrets() {
        typedSecrets = [:]
        forgotten = []
        refreshStoredSecrets()
    }

    /// Counts the lookups, so a slow one never overwrites a later one.
    private var secretsLookup = 0

    /// Asks the Keychain off the main thread: the interface never waits
    /// for it.
    private func refreshStoredSecrets() {
        secretsLookup += 1
        let lookup = secretsLookup
        guard let id = original else {
            storedSecrets = []
            return
        }
        let client = model.client
        Task {
            let stored = await Task.detached {
                Set(["psk", "password", "private_key"].filter { client.hasSecret(id: id, key: $0) })
            }.value
            if lookup == secretsLookup { storedSecrets = stored }
        }
    }

    /// The folder shown instead of a VPN.
    @Published private(set) var selectedFolder: String?
    /// Folders made with New Folder that no VPN is filed in yet.
    @Published private(set) var emptyFolders: [String] = Settings.emptyFolders {
        didSet { Settings.emptyFolders = emptyFolders }
    }

    /// Every folder, empty ones included.
    var folders: [String] { allFolders(model.profiles, extra: emptyFolders) }

    /// List tags of folders, apart from profile names.
    static func folderTag(_ path: String) -> String { "\u{1}folder:" + path }

    static func folder(of tag: String) -> String? {
        tag.hasPrefix("\u{1}folder:") ? String(tag.dropFirst("\u{1}folder:".count)) : nil
    }

    /// The folder a list row stands for: by its tag, or by its path if the
    /// list used the row's identity instead.
    func folderFor(_ id: String) -> String? {
        Self.folder(of: id) ?? (folders.contains(id) && !model.profiles.contains { $0.id == id } ? id : nil)
    }

    /// The list selection: picking another VPN asks about unsaved changes.
    var selectionBinding: Binding<String?> {
        Binding(get: { self.selectedFolder.map(Self.folderTag) ?? self.selection }, set: { tag in
            // A folder row: its tag, or the folder path itself if the list
            // used the row's identity instead.
            if let folder = tag.flatMap(self.folderFor) {
                guard folder != self.selectedFolder else { return }
                DispatchQueue.main.async {
                    self.leave {
                        self.select(nil)
                        self.selectedFolder = folder
                    }
                }
                return
            }
            guard tag != self.selection || self.isNew || self.selectedFolder != nil else { return }
            // The question is asked outside the list's update.
            DispatchQueue.main.async {
                self.leave { self.select(tag) }
            }
        })
    }

    /// A new folder, inside `parent` if given; kept until a VPN is filed
    /// in it.
    func newFolder(in parent: String?) {
        guard let name = Self.askFolder(title: String(localized: "New Folder"), proposed: "") else { return }
        let path = parent.map { "\($0)/\(name)" } ?? name
        if !folders.contains(path) { emptyFolders.append(path) }
        if let parent { collapsed.remove(parent) }
    }

    /// Files dragged VPNs in `folder`, just before `before` when dropped on
    /// a VPN (last otherwise).
    func drop(_ ids: [String], folder: String?, before: String?) {
        let known = Set(model.profiles.map(\.id))
        let ids = ids.filter { known.contains($0) && $0 != before }
        guard !ids.isEmpty else { return }
        leave {
            for id in ids {
                do {
                    try self.model.client.moveProfile(id: id, folder: folder, before: before)
                } catch {
                    let name = self.model.displayName(id)
                    Windows.shared.alert(String(localized: "Cannot move “\(name)”"), describe(error))
                }
            }
            self.profilesMoved()
        }
    }

    private func profilesMoved() {
        model.reloadProfiles()
        let used = Set(allFolders(model.profiles))
        emptyFolders.removeAll { used.contains($0) }
        if let selection { select(selection) }
    }

    func start() {
        model.reloadProfiles()
        if selection == nil && form == nil { select(model.profiles.first?.id) }
    }

    func select(_ id: String?) {
        selection = id
        if id != nil { selectedFolder = nil }
        error = nil
        defer { clearSecrets() }
        guard let id else {
            form = nil
            saved = nil
            original = nil
            return
        }
        do {
            let loaded = try model.client.profileForm(id: id)
            form = loaded
            saved = loaded
            original = id
        } catch {
            form = nil
            saved = nil
            original = nil
            self.error = describe(error)
        }
    }

    func startNew(_ kind: VpnKind) {
        leave {
            self.selection = nil
            self.original = nil
            self.saved = nil
            self.error = nil
            self.form = self.model.client.newProfileForm(kind: kind)
            self.clearSecrets()
        }
    }

    /// Drops the edits; a new profile is abandoned.
    func revert() {
        if isNew {
            select(model.profiles.first?.id)
        } else {
            form = saved
            error = nil
            clearSecrets()
        }
    }

    @discardableResult
    func save() -> Bool {
        guard let form else { return false }
        do {
            let id = try model.client.saveProfile(original: original, form: form)
            model.reloadProfiles()
            selection = id
            original = id
            saved = form
            error = nil
            var remove = forgotten
            if !form.savePassword { remove.insert("password") }
            for key in remove { _ = try model.client.deleteSecret(id: id, key: key) }
            for (key, value) in typedSecrets where !value.isEmpty {
                if key == "password" && !form.savePassword { continue }
                try model.client.setSecret(id: id, key: key, value: value)
            }
            clearSecrets()
            return true
        } catch {
            self.error = describe(error)
            return false
        }
    }

    /// Runs `then` once the edits are saved or dropped, as the user chooses;
    /// nothing happens if they cancel or the profile cannot be saved.
    func leave(then: @escaping () -> Void) {
        guard hasChanges, let form else {
            then()
            return
        }
        let alert = NSAlert()
        let name = form.name.isEmpty ? String(localized: "New VPN") : form.name
        alert.messageText = isNew
            ? String(localized: "Create the VPN “\(name)”?")
            : String(localized: "Save the changes made to “\(name)”?")
        alert.informativeText = String(localized: "Your changes are lost if you don’t save them.")
        alert.addButton(withTitle: isNew ? String(localized: "Create") : String(localized: "Save"))
        alert.addButton(withTitle: String(localized: "Cancel"))
        alert.addButton(withTitle: String(localized: "Don’t Save")).hasDestructiveAction = true
        NSApp.activate()
        switch alert.runModal() {
        case .alertFirstButtonReturn:
            if save() { then() }
        case .alertThirdButtonReturn:
            self.form = saved
            clearSecrets()
            then()
        default:
            break
        }
    }

    /// Whether the window may close now (unsaved changes asked about).
    func shouldClose() -> Bool {
        var close = false
        leave { close = true }
        if close { select(nil) }
        return close
    }

    /// Folders the user closed in the list.
    @Published var collapsed: Set<String> = []

    func expanded(_ folder: String) -> Binding<Bool> {
        Binding(get: { !self.collapsed.contains(folder) }, set: { open in
            if open { self.collapsed.remove(folder) } else { self.collapsed.insert(folder) }
        })
    }

    /// Files the profile `id` in `folder` (nil: the top level), unsaved
    /// edits asked about first.
    func move(_ id: String, to folder: String?) {
        drop([id], folder: folder, before: nil)
    }

    /// Renames a folder: the profiles in it and in its subfolders move.
    func renameFolder(_ path: String) {
        let last = path.split(separator: "/").last.map(String.init) ?? path
        guard let typed = Self.askFolder(title: String(localized: "Rename “\(last)”"), proposed: path), typed != path
        else { return }
        leave {
            for profile in self.model.profiles {
                guard let folder = profile.folder, folder == path || folder.hasPrefix(path + "/") else { continue }
                do {
                    try self.model.client.moveProfile(
                        id: profile.id, folder: typed + folder.dropFirst(path.count), before: nil)
                } catch {
                    Windows.shared.alert(String(localized: "Cannot move “\(profile.name)”"), describe(error))
                }
            }
            self.emptyFolders = self.emptyFolders.map { f in
                f == path || f.hasPrefix(path + "/") ? typed + f.dropFirst(path.count) : f
            }
            if let shown = self.selectedFolder, shown == path || shown.hasPrefix(path + "/") {
                self.selectedFolder = typed + shown.dropFirst(path.count)
            }
            self.profilesMoved()
        }
    }

    static func askFolder(title: String, proposed: String) -> String? {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = String(localized: "“/” separates subfolders, as in Clients/Acme.")
        let field = NSTextField(string: proposed)
        field.frame = NSRect(x: 0, y: 0, width: 260, height: 24)
        alert.accessoryView = field
        alert.addButton(withTitle: String(localized: "OK"))
        alert.addButton(withTitle: String(localized: "Cancel"))
        alert.window.initialFirstResponder = field
        NSApp.activate()
        guard alert.runModal() == .alertFirstButtonReturn else { return nil }
        let typed = field.stringValue.split(separator: "/").map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }.joined(separator: "/")
        return typed.isEmpty ? nil : typed
    }

    /// Renames the profile `id`, asked in a dialog. Unsaved edits are
    /// asked about first. Only the name changes: the id, the secrets, a
    /// running session and the chains stay.
    /// Copies `id`, with its saved secrets, and opens the copy.
    func duplicate(_ id: String) {
        leave {
            let name = self.model.profile(id)?.name ?? id
            do {
                let copy = try self.model.client.duplicateProfile(id: id, name: String(localized: "\(name) copy"))
                self.model.reloadProfiles()
                self.select(copy.id)
                if let reason = copy.secretsError {
                    Windows.shared.alert(String(localized: "The saved secrets of “\(name)” were not copied"),
                                         String(localized: "Type them in the copy's editor. \(reason)"))
                }
            } catch {
                Windows.shared.alert(String(localized: "Cannot duplicate “\(name)”"), describe(error))
            }
        }
    }

    func rename(_ id: String) {
        leave {
            self.select(id)
            guard var form = self.saved else { return }
            let name = form.name
            var proposed = name
            while true {
                guard let typed = Self.askName(for: name, proposed: proposed) else { return }
                proposed = typed
                if typed == name { return }
                form.name = typed
                do {
                    _ = try self.model.client.saveProfile(original: id, form: form)
                    self.model.reloadProfiles()
                    self.select(id)
                    return
                } catch {
                    Windows.shared.alert(String(localized: "Cannot rename “\(name)”"), describe(error))
                }
            }
        }
    }

    private static func askName(for name: String, proposed: String) -> String? {
        let alert = NSAlert()
        alert.messageText = String(localized: "Rename “\(name)”")
        alert.informativeText = String(localized: "Up to 64 characters, without “/”; unique in its folder.")
        let field = NSTextField(string: proposed)
        field.frame = NSRect(x: 0, y: 0, width: 260, height: 24)
        alert.accessoryView = field
        alert.addButton(withTitle: String(localized: "Rename"))
        alert.addButton(withTitle: String(localized: "Cancel"))
        alert.window.initialFirstResponder = field
        NSApp.activate()
        guard alert.runModal() == .alertFirstButtonReturn else { return nil }
        let typed = field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        return typed.isEmpty ? nil : typed
    }

    /// Deletes the profile `id`, once confirmed; the one being edited is
    /// replaced by the first profile.
    func delete(_ id: String) {
        let name = model.displayName(id)
        if model.isOn(id) {
            Windows.shared.alert(String(localized: "“\(name)” is connected"),
                                 String(localized: "Disconnect it before deleting it."))
            return
        }
        let alert = NSAlert()
        alert.messageText = String(localized: "Delete “\(name)”?")
        alert.informativeText = String(localized: "The profile and its saved secrets are removed. The other profiles and the comments in your file are left unchanged.")
        alert.addButton(withTitle: String(localized: "Delete")).hasDestructiveAction = true
        alert.addButton(withTitle: String(localized: "Cancel"))
        NSApp.activate()
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        do {
            // The profile first: if it stays, so do its secrets (a WireGuard
            // private key cannot be recovered).
            try model.client.removeProfile(id: id)
            for key in ["password", "psk", "private_key"] { _ = try? model.client.deleteSecret(id: id, key: key) }
            model.reloadProfiles()
            model.forget(id)
            if id == selection {
                form = nil
                select(model.profiles.first?.id)
            }
        } catch {
            Windows.shared.alert(String(localized: "Cannot delete the profile"), describe(error))
        }
    }
}

struct ManageView: View {
    @ObservedObject var model: AppModel
    @ObservedObject var editing: ProfileEditing

    var body: some View {
        NavigationSplitView {
            List(selection: editing.selectionBinding) {
                FolderContents(editing: editing, profiles: model.profiles, folders: editing.folders, folder: nil)
            }
            // Dropped outside any folder: to the top level, last.
            .dropDestination(for: String.self) { names, _ in
                editing.drop(names, folder: nil, before: nil)
                return true
            }
            // Double-click renames; the context menu offers the same.
            .contextMenu(forSelectionType: String.self) { ids in
                if let id = ids.first, let folder = editing.folderFor(id) {
                    Button("New Folder Inside…") { editing.newFolder(in: folder) }
                    Button("Rename Folder…") { editing.renameFolder(folder) }
                } else if let id = ids.first {
                    Button("Rename…") { editing.rename(id) }
                    Button("Duplicate") { editing.duplicate(id) }
                    Divider()
                    ConnectButtons(model: model, id: id)
                    Divider()
                    Menu("Move to Folder") {
                        Button("None") { editing.move(id, to: nil) }
                        if !editing.folders.isEmpty {
                            Divider()
                            ForEach(editing.folders, id: \.self) { folder in
                                Button(folder) { editing.move(id, to: folder) }
                            }
                        }
                        Divider()
                        Button("New Folder…") {
                            if let folder = ProfileEditing.askFolder(title: String(localized: "New Folder"), proposed: "") {
                                editing.move(id, to: folder)
                            }
                        }
                    }
                    Divider()
                    Button("Delete…") { editing.delete(id) }
                }
            } primaryAction: { ids in
                if let id = ids.first {
                    if let folder = editing.folderFor(id) { editing.renameFolder(folder) } else { editing.rename(id) }
                }
            }
            .safeAreaInset(edge: .bottom) {
                HStack(spacing: 4) {
                    Menu {
                        Button("SSL VPN (FortiGate)") { editing.startNew(.fortiSsl) }
                        Button("IPsec") { editing.startNew(.ipsec) }
                        Button("OpenVPN") { editing.startNew(.openVpn) }
                        Button("L2TP over IPsec") { editing.startNew(.l2tp) }
                        Button("WireGuard") { editing.startNew(.wireGuard) }
                        Divider()
                        Button("New Folder…") { editing.newFolder(in: editing.selectedFolder) }
                    } label: {
                        Image(systemName: "plus")
                    }
                    .menuIndicator(.hidden)
                    .fixedSize()
                    .help("New VPN")
                    Button {
                        if let id = editing.selection { editing.delete(id) }
                    } label: {
                        Image(systemName: "minus")
                    }
                    .disabled(editing.selection == nil)
                    .help("Delete")
                    Spacer()
                    Menu("Import") {
                        Button("Profile File (.vpnprofile)…") { importFile() }
                        Button("From All Other VPN Apps…") { Windows.shared.showSetup(model: model) }
                        Divider()
                        Button("OpenVPN or WireGuard File (.ovpn, .conf)…") { Windows.shared.importOpenVpn(model: model) }
                        Button("From FortiClient…") { Windows.shared.showImport(model: model) }
                        Button("From Viscosity…") { Windows.shared.showViscosityImport(model: model) }
                        Button("From System Settings…") { Windows.shared.showMacImport(model: model) }
                    }
                    .fixedSize()
                }
                .buttonStyle(.borderless)
                .padding(8)
            }
            .navigationSplitViewColumnWidth(min: 180, ideal: 200)
        } detail: {
            if let shown = editing.form {
                // Not Binding($editing.form): its force unwrap crashes the
                // app when the form is dropped (window closed, VPN deleted)
                // while the editor is still being drawn.
                ProfileEditor(model: model, editing: editing, form: Binding(
                    get: { editing.form ?? shown },
                    set: { editing.form = $0 }))
            } else if let folder = editing.selectedFolder {
                FolderOverview(model: model, editing: editing, folder: folder)
            } else if let error = editing.error {
                Label(error, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red).padding()
            } else {
                Text("Select a VPN, or create one with +.").foregroundStyle(.secondary)
            }
        }
        .frame(minWidth: 760, minHeight: 540)
        .onAppear { editing.start() }
    }

    private func importFile() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [UTType(filenameExtension: "vpnprofile") ?? .data]
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Windows.shared.showReceived(model: model, url: url)
    }
}

/// Every folder the profiles use, and `extra` ones, parents included,
/// sorted.
func allFolders(_ profiles: [ProfileSummary], extra: [String] = []) -> [String] {
    var folders = Set<String>()
    for folder in profiles.compactMap(\.folder) + extra {
        let names = folder.split(separator: "/").map(String.init)
        for depth in 1...max(1, names.count) where depth <= names.count {
            folders.insert(names[..<depth].joined(separator: "/"))
        }
    }
    return folders.sorted { $0.localizedStandardCompare($1) == .orderedAscending }
}

/// The subfolders, then the VPNs, of `folder` (nil: the top level). VPNs
/// are dragged onto a folder to file them, onto another VPN to go before it.
private struct FolderContents: View {
    @ObservedObject var editing: ProfileEditing
    let profiles: [ProfileSummary]
    /// Every folder, empty ones included.
    let folders: [String]
    let folder: String?

    private var subfolders: [String] {
        let prefix = folder.map { $0 + "/" } ?? ""
        return folders.filter { $0.hasPrefix(prefix) && !$0.dropFirst(prefix.count).contains("/") }
    }

    var body: some View {
        ForEach(subfolders, id: \.self) { path in
            DisclosureGroup(isExpanded: editing.expanded(path)) {
                FolderContents(editing: editing, profiles: profiles, folders: folders, folder: path)
            } label: {
                Label(String(path.split(separator: "/").last ?? ""), systemImage: "folder")
                    .tag(ProfileEditing.folderTag(path))
                    .dropDestination(for: String.self) { names, _ in
                        editing.drop(names, folder: path, before: nil)
                        return true
                    }
            }
        }
        ForEach(profiles.filter { $0.folder == folder }, id: \.id) { profile in
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: profile.name)
                Text(verbatim: kindName(profile.protocol)).font(.caption).foregroundStyle(.secondary)
            }
            .tag(profile.id)
            .draggable(profile.id)
            .dropDestination(for: String.self) { ids, _ in
                editing.drop(ids, folder: profile.folder, before: profile.id)
                return true
            }
        }
    }
}

/// Connects or disconnects the VPN `id`, as the menu bar does: also in
/// split mode, or without the VPNs it goes through, when it has them.
private struct ConnectButtons: View {
    @ObservedObject var model: AppModel
    let id: String

    var body: some View {
        if model.isOn(id) {
            Button("Disconnect") { model.toggle(id, on: false) }
        } else {
            Button("Connect") { model.connect(id) }
            if let profile = model.profile(id) {
                if !profile.splitRoutes.isEmpty {
                    Button("Connect in Split Mode") { model.connect(id, split: true) }
                }
                if !profile.via.isEmpty {
                    Button("Connect Directly, Without \(profile.via.map(model.displayName).joined(separator: " / "))") {
                        model.connect(id, direct: true)
                    }
                }
            }
        }
    }
}

/// A folder selected in the list: its VPNs, to connect or open.
private struct FolderOverview: View {
    @ObservedObject var model: AppModel
    @ObservedObject var editing: ProfileEditing
    let folder: String

    private var inside: [ProfileSummary] {
        model.profiles.filter { $0.folder.map { $0 == folder || $0.hasPrefix(folder + "/") } ?? false }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Label(folder, systemImage: "folder").font(.title3.bold())
                Spacer()
                Button("Rename…") { editing.renameFolder(folder) }
            }
            .padding()
            if inside.isEmpty {
                Text("Drag VPNs here from the list to file them in this folder.")
                    .foregroundStyle(.secondary).padding()
                Spacer()
            } else {
                List(inside, id: \.id) { profile in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(verbatim: profile.name)
                            let sub = profile.folder.map { $0 == folder ? "" : " · \($0.dropFirst(folder.count + 1))" } ?? ""
                            Text(verbatim: "\(kindName(profile.protocol)) · \(profile.host)\(sub)")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button("Edit") { editing.leave { editing.select(profile.id) } }
                        Toggle("", isOn: Binding(get: { model.isOn(profile.id) },
                                                 set: { model.toggle(profile.id, on: $0) }))
                            .toggleStyle(.switch).labelsHidden()
                    }
                }
            }
        }
    }
}

func kindName(_ protocolName: String) -> String {
    switch protocolName {
    case "ipsec": "IPsec"
    case "openvpn": "OpenVPN"
    case "l2tp": "L2TP"
    case "wireguard": "WireGuard"
    default: String(localized: "SSL VPN")
    }
}

func kindName(_ kind: VpnKind) -> String {
    switch kind {
    case .ipsec: "IPsec"
    case .openVpn: "OpenVPN"
    case .l2tp: "L2TP"
    case .wireGuard: "WireGuard"
    case .fortiSsl: String(localized: "SSL VPN")
    }
}

/// The editor of one profile. IPsec follows FortiClient's layout: the
/// connection on the General tab, IKE and the two phases on Advanced.
struct ProfileEditor: View {
    @ObservedObject var model: AppModel
    @ObservedObject var editing: ProfileEditing
    @Binding var form: ProfileForm

    private var original: String? { editing.original }
    private var isConnected: Bool { original.map { model.sessions[$0] != nil } ?? false }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            TabView {
                GeneralTab(editing: editing, form: $form).tabItem { Text("General") }
                if form.kind == .ipsec {
                    IpsecAdvancedTab(form: $form).tabItem { Text("Advanced") }
                }
                NetworkTab(form: $form, others: model.profiles.filter { $0.id != original }.map { ($0.id, $0.name) })
                    .tabItem { Text("Network") }
            }
            .padding(.horizontal)
            footer
        }
    }

    /// The server, or OpenVPN's first one.
    private var server: String {
        let (host, port) = form.kind == .openVpn
            ? (form.servers.first?.host ?? "", form.servers.first?.port ?? 0) : (form.host, form.port)
        return "\(host)\(port == 0 ? "" : ":\(port)")"
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: form.name.isEmpty ? String(localized: "New VPN") : form.name).font(.title3.bold())
                Text(verbatim: "\(kindName(form.kind)) · \(server)")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if let original {
                // The saved profile connects: edits are asked about first.
                Toggle("", isOn: Binding(get: { model.isOn(original) },
                                         set: { on in
                                             if on { editing.leave { model.connect(original) } } else { model.toggle(original, on: false) }
                                         }))
                    .toggleStyle(.switch).labelsHidden()
                    .help(model.isOn(original) ? String(localized: "Disconnect") : String(localized: "Connect"))
                Menu {
                    ConnectButtons(model: model, id: original)
                    Divider()
                    Button("Export as a Profile File…") { export(original) }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
                .menuIndicator(.hidden)
                .fixedSize()
            }
        }
        .padding()
    }

    private var footer: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let error = editing.error {
                Label(error, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                if editing.isNew {
                    Text("The VPN is added when you click Create.").font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Button("Cancel") { editing.revert() }.keyboardShortcut(.cancelAction)
                    Button("Create") { editing.save() }.keyboardShortcut(.defaultAction)
                } else {
                    if editing.hasChanges {
                        Label("Unsaved changes", systemImage: "circle.fill")
                            .font(.caption).foregroundStyle(.orange).labelStyle(.titleAndIcon)
                            .imageScale(.small)
                    } else if isConnected {
                        Text("Changes apply at the next connection.").font(.caption).foregroundStyle(.secondary)
                    } else {
                        Text("All changes are saved.").font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    if isConnected, let original {
                        Button("Save and Reconnect") {
                            guard !editing.hasChanges || editing.save() else { return }
                            Task {
                                try? await model.client.disconnect(id: original)
                                model.connectAgain(original)
                            }
                        }
                    }
                    Button("Revert") { editing.revert() }.disabled(!editing.hasChanges)
                    Button("Save") { editing.save() }.keyboardShortcut(.defaultAction).disabled(!editing.hasChanges)
                }
            }
        }
        .padding()
    }

    private func export(_ id: String) {
        do {
            let text = try model.client.exportProfile(id: id)
            let panel = NSSavePanel()
            panel.nameFieldStringValue = "\(model.displayName(id)).vpnprofile"
            panel.allowedContentTypes = [UTType(filenameExtension: "vpnprofile") ?? .data]
            guard panel.runModal() == .OK, let url = panel.url else { return }
            try writePrivately(text, to: url)
        } catch {
            Windows.shared.alert(String(localized: "Cannot export the profile"), describe(error))
        }
    }
}

/// Writes `text` to `url` readable by its owner only, from the start: its
/// shared keys are for the VPN's users, not everyone on this Mac. The file
/// is created 0600 beside `url`, then renamed over it.
private func writePrivately(_ text: String, to url: URL) throws {
    let temp = url.deletingLastPathComponent().appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString)")
    let fd = open(temp.path, O_WRONLY | O_CREAT | O_EXCL, 0o600)
    guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    do {
        try handle.write(contentsOf: Data(text.utf8))
        try handle.synchronize()
        try handle.close()
        guard rename(temp.path, url.path) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    } catch {
        unlink(temp.path)
        throw error
    }
}

/// An optional text field: empty means unset.
private func optional(_ binding: Binding<String?>) -> Binding<String> {
    Binding(get: { binding.wrappedValue ?? "" }, set: { binding.wrappedValue = $0.isEmpty ? nil : $0 })
}

/// A list edited as one entry per line.
extension ListEntry {
    /// `10.20.0.5/32 (Jira)`, or the value alone.
    var described: String { note.isEmpty ? value : "\(value) (\(note))" }
}

/// A list of networks or domains, each with a note to remember what it is
/// for: one row per entry, checked as it is typed; several lines can be
/// pasted at once (`10.1.0.0/16  Intranet`). Empty rows are dropped when
/// the VPN is saved.
private struct NotedList: View {
    enum Kind {
        /// A network, or a domain routed as it resolves.
        case network
        /// A DNS domain.
        case domain
        /// A domain to keep outside the VPN (`*.` for every name under it).
        case pattern
    }

    let title: LocalizedStringKey
    @Binding var entries: [ListEntry]
    let kind: Kind

    private var placeholder: String {
        switch kind {
        case .network: "10.1.0.0/16, *.corp.example"
        case .domain: "corp.example"
        case .pattern: "*.zoom.us"
        }
    }

    private func error(_ value: String) -> String? {
        let value = value.trimmingCharacters(in: .whitespaces)
        guard !value.isEmpty else { return nil }
        switch kind {
        case .network: return networkError(text: value)
        case .domain: return domainError(text: value)
        case .pattern: return patternError(text: value)
        }
    }

    /// Row `i`'s field, safe while rows are removed.
    private func field(_ i: Int, _ path: WritableKeyPath<ListEntry, String>) -> Binding<String> {
        Binding(get: { i < entries.count ? entries[i][keyPath: path] : "" },
                set: { if i < entries.count { entries[i][keyPath: path] = $0 } })
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
            Grid(alignment: .leading, horizontalSpacing: 6, verticalSpacing: 4) {
                ForEach(Array(entries.indices), id: \.self) { i in
                    GridRow {
                        // In a Form a title becomes a label: prompts only.
                        TextField("", text: field(i, \.value), prompt: Text(verbatim: placeholder))
                            .font(.system(.body, design: .monospaced)).frame(minWidth: 150, idealWidth: 170)
                        TextField("", text: field(i, \.note), prompt: Text("Note"))
                        if let error = error(entries[i].value) {
                            Image(systemName: "exclamationmark.circle.fill").foregroundStyle(.red).help(error)
                        } else {
                            Image(systemName: "exclamationmark.circle.fill").hidden()
                        }
                        Button { entries.remove(at: i) } label: { Image(systemName: "minus.circle") }
                            .buttonStyle(.borderless).help(String(localized: "Remove"))
                    }
                }
            }
            .labelsHidden().textFieldStyle(.roundedBorder).multilineTextAlignment(.leading)
            HStack(spacing: 12) {
                Button { entries.append(ListEntry(value: "", note: "")) } label: { Label("Add", systemImage: "plus") }
                Button { paste() } label: { Label("Paste Lines", systemImage: "doc.on.clipboard") }
                    .help(String(localized: "One entry per line: the network or domain, then its note"))
            }
            .buttonStyle(.borderless).font(.callout)
        }
    }

    private func paste() {
        guard let text = NSPasteboard.general.string(forType: .string) else { return }
        // A blank last row is replaced, not kept before the pasted ones.
        if let last = entries.last, last.value.isEmpty, last.note.isEmpty { entries.removeLast() }
        entries += parseList(text: text)
    }
}

private func lines(_ binding: Binding<[String]>) -> Binding<String> {
    Binding(get: { binding.wrappedValue.joined(separator: "\n") },
            set: { binding.wrappedValue = $0.components(separatedBy: .newlines) })
}

private func port(_ binding: Binding<UInt16>) -> Binding<String> {
    Binding(get: { binding.wrappedValue == 0 ? "" : String(binding.wrappedValue) },
            set: { binding.wrappedValue = UInt16($0.filter(\.isNumber)) ?? 0 })
}

private func number(_ binding: Binding<UInt32>) -> Binding<String> {
    Binding(get: { String(binding.wrappedValue) },
            set: { binding.wrappedValue = UInt32($0.filter(\.isNumber).prefix(9)) ?? 0 })
}

/// A secret typed in the editor; the placeholder tells whether one is saved.
private struct SecretField: View {
    @ObservedObject var editing: ProfileEditing
    let key: String
    let label: LocalizedStringKey

    var body: some View {
        LabeledContent(label) {
            HStack {
                SecureField("", text: editing.secret(key), prompt: Text(editing.isStored(key)
                    ? String(localized: "Saved in the Keychain") : String(localized: "Asked at connection")))
                    .labelsHidden()
                if editing.isStored(key) {
                    Button("Forget") { editing.forget(key) }
                        .help("Removes the saved value from the Keychain when you save.")
                }
            }
        }
    }
}

/// FortiClient's XAuth choice.
private enum XauthChoice: Hashable {
    case ask, save, off
}

private struct GeneralTab: View {
    @ObservedObject var editing: ProfileEditing
    @Binding var form: ProfileForm
    @State private var advanced = false

    private var xauth: Binding<XauthChoice> {
        Binding(get: { !form.xauth ? .off : form.savePassword ? .save : .ask }, set: {
            form.xauth = $0 != .off
            form.savePassword = $0 != .ask
        })
    }

    private var gatewayCertificate: Bool { form.ikeVersion == 2 && form.gatewayCertificate }
    private var clientCertificate: Bool { form.ikeVersion == 2 && form.clientCertificate != nil }

    var body: some View {
        Form {
            Section {
                if let original = editing.original {
                    LabeledContent("Name") {
                        HStack {
                            Text(verbatim: editing.saved?.name ?? form.name)
                            Button("Rename…") { editing.rename(original) }
                        }
                    }
                } else {
                    TextField("Name", text: $form.name, prompt: Text(verbatim: "paris"))
                }
                TextField("Description", text: optional($form.description), prompt: Text("Optional"))
                LabeledContent("Folder") {
                    HStack(spacing: 4) {
                        TextField("", text: optional($form.folder), prompt: Text("None")).labelsHidden()
                        let folders = editing.folders
                        if !folders.isEmpty {
                            Menu {
                                Button("None") { form.folder = nil }
                                Divider()
                                ForEach(folders, id: \.self) { folder in
                                    Button(folder) { form.folder = folder }
                                }
                            } label: {
                                Image(systemName: "folder")
                            }
                            .menuIndicator(.hidden)
                            .fixedSize()
                            .help("“/” separates subfolders, as in Clients/Acme.")
                        }
                    }
                }
                if form.kind != .openVpn {
                    TextField(form.kind == .ipsec ? "Remote Gateway" : "Server", text: $form.host,
                              prompt: Text(verbatim: "vpn.example.com"))
                }
            }
            if form.kind == .openVpn {
                OpenVpnServersSection(servers: $form.servers)
                Section {
                    Toggle("User name and password", isOn: $form.passwordAuth)
                    if form.passwordAuth {
                        TextField("User Name", text: optional($form.username))
                        Toggle("Save the password in the Keychain", isOn: $form.savePassword)
                        if form.savePassword {
                            SecretField(editing: editing, key: "password", label: "Password")
                        }
                    }
                }
                ClientCertificateSection(form: $form, filesInProfile: form.hasClientCertificate)
                OpenVpnServerCertificateSection(form: $form)
                Section {
                    DisclosureGroup("Advanced Options", isExpanded: $advanced) {
                        OpenVpnAdvancedOptions(form: $form)
                    }
                }
            } else if form.kind == .ipsec {
                Section {
                    if form.ikeVersion == 2 {
                        Picker("Gateway Identity", selection: $form.gatewayCertificate) {
                            Text("Pre-shared key").tag(false)
                            Text("Certificate").tag(true)
                        }
                        .pickerStyle(.radioGroup).horizontalRadioGroupLayout()
                    }
                    if gatewayCertificate && clientCertificate {
                        Text("No pre-shared key: you and the gateway prove your identities with certificates.")
                            .font(.caption).foregroundStyle(.secondary)
                    } else if gatewayCertificate && form.xauth {
                        Text("No pre-shared key: you sign in with your user name and password, the gateway with its certificate.")
                            .font(.caption).foregroundStyle(.secondary)
                    } else {
                        LabeledContent("Authentication Method") { Text("Pre-shared key") }
                        SecretField(editing: editing, key: "psk", label: "Pre-shared Key")
                    }
                }
                if gatewayCertificate {
                    GatewayCertificateSection(form: $form)
                }
                if form.ikeVersion == 2 {
                    ClientCertificateSection(form: $form)
                }
                if !clientCertificate {
                    Section {
                        Picker("Authentication (XAuth)", selection: xauth) {
                            Text("Ask at connection").tag(XauthChoice.ask)
                            Text("Save credentials").tag(XauthChoice.save)
                            Text("Disable").tag(XauthChoice.off)
                        }
                        .pickerStyle(.radioGroup)
                        if form.xauth {
                            TextField("User Name", text: optional($form.username))
                            if form.savePassword {
                                SecretField(editing: editing, key: "password", label: "Password")
                            }
                        }
                    }
                }
            } else if form.kind == .l2tp {
                L2tpSections(editing: editing, form: $form, advanced: $advanced)
            } else if form.kind == .wireGuard {
                WireGuardSections(editing: editing, form: $form, advanced: $advanced)
            } else {
                Section {
                    Picker("Method", selection: $form.saml) {
                        Text("Password").tag(false)
                        Text("SAML (browser)").tag(true)
                    }
                    if !form.saml {
                        TextField("User Name", text: optional($form.username))
                        Toggle("Save the password in the Keychain", isOn: $form.savePassword)
                        if form.savePassword {
                            SecretField(editing: editing, key: "password", label: "Password")
                        }
                    }
                }
                Section {
                    DisclosureGroup("Advanced Options", isExpanded: $advanced) {
                        TextField("Port", text: port($form.port))
                        TextField("Realm", text: optional($form.realm))
                        if form.saml {
                            TextField("SAML Callback Port", text: port($form.samlPort))
                        }
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Trusted certificate fingerprints (SHA-256, one per line)")
                            TextEditor(text: lines($form.trustedCertificates))
                                .font(.system(.caption, design: .monospaced))
                                .frame(minHeight: 44)
                        }
                    }
                }
                ClientCertificateSection(form: $form, filesInProfile: form.hasClientCertificate)
            }
        }
        .formStyle(.grouped)
        .onAppear { advanced = false }
    }
}

/// The Keychain certificate we authenticate with: in IPsec instead of a
/// user name or the pre-shared key, in the SSL VPN instead of PEM files.
private struct ClientCertificateSection: View {
    @Binding var form: ProfileForm
    /// The SSL VPN profile names certificate files.
    var filesInProfile = false
    @State private var identities: [KeychainIdentity] = []
    @State private var error: String?

    var body: some View {
        Section("Client Certificate") {
            Picker("Certificate", selection: $form.clientCertificate) {
                Text("None").tag(String?.none)
                ForEach(identities, id: \.sha256) { identity in
                    Text(verbatim: label(identity)).tag(Optional(identity.sha256))
                }
                if let chosen = form.clientCertificate, !identities.contains(where: { $0.sha256 == chosen }) {
                    Text("Not in the Keychain").tag(Optional(chosen))
                }
            }
            if let error {
                Text(verbatim: error).font(.caption).foregroundStyle(.orange)
            }
            if filesInProfile && form.clientCertificate == nil {
                Text(form.kind == .openVpn
                     ? "The certificate imported with the OpenVPN file is used. A Keychain certificate would replace it."
                     : "The certificate files named in the profile file are used. A Keychain certificate would replace them.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Text(form.clientCertificate == nil
                 ? "Certificates with their private key in your Keychain, such as one installed by your organization."
                 : "The key stays in the Keychain, which may ask you to allow its use at connection.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .onAppear(perform: load)
    }

    private func label(_ identity: KeychainIdentity) -> String {
        let expired = Date(timeIntervalSince1970: TimeInterval(identity.notAfter)) < Date()
        let issuer = String(format: String(localized: "issued by %@"), identity.issuer)
        return expired ? "\(identity.name) (\(issuer), \(String(localized: "expired")))" : "\(identity.name) (\(issuer))"
    }

    private func load() {
        do {
            identities = try keychainIdentities()
            error = nil
        } catch {
            self.error = describe(error)
        }
    }
}

/// The CA that signs the gateway certificate, and pinned fingerprints.
private struct GatewayCertificateSection: View {
    @Binding var form: ProfileForm
    @State private var error: String?

    var body: some View {
        Section("Gateway Certificate") {
            LabeledContent("Certificate Authority") {
                VStack(alignment: .trailing, spacing: 4) {
                    let names = certificateNames(pem: form.caPem ?? "")
                    if names.isEmpty {
                        Text("System and Keychain").foregroundStyle(.secondary)
                    } else {
                        ForEach(names, id: \.self) { Text(verbatim: $0).font(.caption).textSelection(.enabled) }
                    }
                    HStack {
                        Button("Choose…", action: choose)
                        if form.caPem != nil {
                            Button("Remove") { form.caPem = nil }
                        }
                    }
                }
            }
            if let error {
                Text(verbatim: error).font(.caption).foregroundStyle(.orange)
            }
            Text("Authorities trusted by the system or your Keychain, such as those your organization installs, are always accepted.")
                .font(.caption).foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 4) {
                Text("Trusted certificate fingerprints (SHA-256, one per line)")
                TextEditor(text: lines($form.trustedCertificates))
                    .font(.system(.caption, design: .monospaced))
                    .frame(minHeight: 44)
            }
            Text("A certificate that cannot be verified is shown at the first connection, so you can decide to trust it.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private func choose() {
        do {
            if let pem = try chooseCertificates() { form.caPem = pem }
            error = nil
        } catch {
            self.error = describe(error)
        }
    }
}

/// Certificates from a file the user picks, as PEM (nil: cancelled).
@MainActor
private func chooseCertificates() throws -> String? {
    let panel = NSOpenPanel()
    panel.allowedContentTypes = ["pem", "crt", "cer", "der"].compactMap { UTType(filenameExtension: $0) }
        + [.x509Certificate]
    panel.allowsMultipleSelection = false
    guard panel.runModal() == .OK, let url = panel.url else { return nil }
    return try certificatesAsPem(data: Data(contentsOf: url))
}

/// OpenVPN servers (`remote`), tried in order.
private struct OpenVpnServersSection: View {
    @Binding var servers: [OpenVpnServer]

    var body: some View {
        Section("Servers") {
            ForEach(servers.indices, id: \.self) { index in
                HStack {
                    TextField("Server", text: $servers[index].host, prompt: Text(verbatim: "vpn.example.com"))
                        .labelsHidden()
                    TextField("Port", text: port($servers[index].port), prompt: Text(verbatim: "1194"))
                        .labelsHidden().frame(width: 64)
                    Picker("Transport", selection: $servers[index].transport) {
                        Text(verbatim: "UDP").tag(OpenVpnTransport.udp)
                        Text(verbatim: "TCP").tag(OpenVpnTransport.tcp)
                    }
                    .labelsHidden().fixedSize()
                    Button {
                        servers.remove(at: index)
                    } label: {
                        Image(systemName: "minus.circle")
                    }
                    .buttonStyle(.borderless)
                    .disabled(servers.count == 1)
                    .help("Remove")
                }
            }
            Button {
                let last = servers.last
                servers.append(OpenVpnServer(host: "", port: last?.port ?? 1194, transport: last?.transport ?? .udp))
            } label: {
                Label("Add a Server", systemImage: "plus.circle")
            }
            .buttonStyle(.borderless)
            .disabled(servers.count >= 16)
            if servers.count > 1 {
                Text("The servers are tried in this order.").font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}

/// How the OpenVPN server's certificate is checked: its own CA only, or
/// pinned fingerprints, and its name.
private struct OpenVpnServerCertificateSection: View {
    @Binding var form: ProfileForm
    @State private var error: String?

    var body: some View {
        Section("Server Certificate") {
            LabeledContent("Certificate Authority") {
                VStack(alignment: .trailing, spacing: 4) {
                    let names = certificateNames(pem: form.caPem ?? "")
                    if names.isEmpty {
                        Text("None").foregroundStyle(.secondary)
                    } else {
                        ForEach(names, id: \.self) { Text(verbatim: $0).font(.caption).textSelection(.enabled) }
                    }
                    HStack {
                        Button("Choose…", action: choose)
                        if form.caPem != nil {
                            Button("Remove") { form.caPem = nil }
                        }
                    }
                }
            }
            if let error {
                Text(verbatim: error).font(.caption).foregroundStyle(.orange)
            }
            Text("Only this authority is trusted, not the system's: OpenVPN servers have their own.")
                .font(.caption).foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 4) {
                Text("Trusted certificate fingerprints (SHA-256, one per line)")
                TextEditor(text: lines($form.trustedCertificates))
                    .font(.system(.caption, design: .monospaced))
                    .frame(minHeight: 44)
            }
            Text("With fingerprints, only these certificates are accepted and the authority is not needed.")
                .font(.caption).foregroundStyle(.secondary)
            TextField("Server Name", text: optional($form.verifyX509Name), prompt: Text("Optional"))
                .help("The name the server certificate must carry (verify-x509-name).")
            if form.verifyX509Name != nil {
                Picker("Compared With", selection: $form.verifyX509Match) {
                    Text("Whole subject").tag(X509NameMatch.subject)
                    Text("Common name").tag(X509NameMatch.name)
                    Text("Start of the common name").tag(X509NameMatch.namePrefix)
                }
            }
            Toggle("Require a certificate meant for a server", isOn: $form.remoteCertTls)
                .help("remote-cert-tls server")
            if !form.remoteCertTls {
                Label("Without it, any client of the same authority could pose as the server.",
                      systemImage: "exclamationmark.triangle.fill")
                    .font(.caption).foregroundStyle(.orange)
            }
        }
    }

    private func choose() {
        do {
            if let pem = try chooseCertificates() { form.caPem = pem }
            error = nil
        } catch {
            self.error = describe(error)
        }
    }
}

private let openVpnCiphers = ["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"]
private let openVpnDigests = ["SHA1", "SHA256", "SHA384", "SHA512"]

/// The rest of an OpenVPN configuration, rarely changed.
private struct OpenVpnAdvancedOptions: View {
    @Binding var form: ProfileForm
    @State private var keyError: String?

    private func cipher(_ name: String) -> Binding<Bool> {
        Binding(get: { form.dataCiphers.contains(name) }, set: { on in
            form.dataCiphers.removeAll { $0.caseInsensitiveCompare(name) == .orderedSame }
            if on { form.dataCiphers.append(name) }
        })
    }

    var body: some View {
        Picker("Control Channel", selection: $form.controlChannel) {
            Text("None").tag(OpenVpnControlChannel.none)
            Text(verbatim: "tls-auth").tag(OpenVpnControlChannel.tlsAuth)
            Text(verbatim: "tls-crypt").tag(OpenVpnControlChannel.tlsCrypt)
        }
        if form.controlChannel != .none {
            LabeledContent("Static Key") {
                HStack {
                    Text(form.staticKey == nil ? "None" : "OpenVPN static key").foregroundStyle(.secondary)
                    Button("Choose…", action: chooseKey)
                }
            }
            if let keyError {
                Text(verbatim: keyError).font(.caption).foregroundStyle(.orange)
            }
            if form.controlChannel == .tlsAuth {
                Picker("Key Direction", selection: $form.keyDirection) {
                    Text("Both directions").tag(UInt8?.none)
                    Text(verbatim: "0").tag(UInt8?.some(0))
                    Text(verbatim: "1").tag(UInt8?.some(1))
                }
                Picker("HMAC Digest", selection: $form.authDigest) {
                    ForEach(openVpnDigests, id: \.self) { Text(verbatim: $0).tag($0) }
                }
            }
        }
        LabeledContent("Data Ciphers") {
            VStack(alignment: .leading) {
                ForEach(openVpnCiphers, id: \.self) { Toggle($0, isOn: cipher($0)) }
            }
        }
        if form.dataCiphers.isEmpty {
            Label("Choose at least one cipher.", systemImage: "exclamationmark.triangle.fill")
                .font(.caption).foregroundStyle(.orange)
        }
        Picker("Compression", selection: $form.compression) {
            Text("None").tag(OpenVpnCompression.none)
            Text(verbatim: "comp-lzo").tag(OpenVpnCompression.lzo)
            Text(verbatim: "compress").tag(OpenVpnCompression.stub)
            Text(verbatim: "compress stub-v2").tag(OpenVpnCompression.stubV2)
        }
        Text("Packets are never compressed: choose the framing the server expects.")
            .font(.caption).foregroundStyle(.secondary)
        LabeledContent("Renegotiate Keys Every") {
            HStack {
                TextField("", text: number($form.renegSec)).labelsHidden().frame(width: 90)
                Text("seconds")
            }
        }
        if form.passwordAuth {
            TextField("Code Question", text: optional($form.staticChallenge), prompt: Text("Optional"))
                .help("A one-time code asked with the password (static-challenge).")
            if form.staticChallenge != nil {
                Toggle("Show the code while it is typed", isOn: $form.staticChallengeEcho)
            }
        }
    }

    private func chooseKey() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let text = try String(contentsOf: url, encoding: .utf8)
            guard text.contains("-----BEGIN OpenVPN Static key V1-----") else {
                keyError = String(localized: "This file is not an OpenVPN static key.")
                return
            }
            form.staticKey = text
            keyError = nil
        } catch {
            keyError = describe(error)
        }
    }
}

private let encryptions: [(String, String)] = [
    ("aes128", "AES128"), ("aes192", "AES192"), ("aes256", "AES256"),
    ("aes128gcm16", "AES128-GCM"), ("aes256gcm16", "AES256-GCM"), ("chacha20poly1305", "ChaCha20-Poly1305"),
    ("3des", "3DES"),
]

/// AES-GCM and ChaCha20-Poly1305 carry their own integrity check.
private func isAead(_ encryption: String) -> Bool {
    encryption.contains("gcm") || encryption == "chacha20poly1305"
}

/// Only offered with legacy algorithms allowed (old gateways).
private let legacyGroup: UInt16 = 2
private let hashes: [(String, String)] = [("sha1", "SHA1"), ("sha256", "SHA256"), ("sha384", "SHA384"), ("sha512", "SHA512")]
/// DH groups the engine supports, with what they are.
private let dhGroups: [(UInt16, String)] = [
    (2, "MODP 1024"), (5, "MODP 1536"), (14, "MODP 2048"), (15, "MODP 3072"), (16, "MODP 4096"),
    (17, "MODP 6144"), (18, "MODP 8192"), (19, "ECP 256"), (20, "ECP 384"), (21, "ECP 521"), (31, "Curve25519"),
]

/// Strongest first.
private let dhStrength: [UInt16] = [21, 20, 19, 31, 18, 17, 16, 15, 14, 5, 2]

/// The DH groups offered: group 2 only for old gateways (or when it is
/// already chosen, so it can be unchecked).
private func offeredGroups(_ form: ProfileForm) -> [(UInt16, String)] {
    dhGroups.filter { id, _ in
        id != legacyGroup || form.legacyAlgorithms || form.phase1DhGroups.contains(id) || form.pfsGroup == id
    }
}

/// The phase 1 DH groups, as checkboxes.
private struct DhGroupsRow: View {
    @Binding var form: ProfileForm

    /// Checked groups are offered strongest first: in IKEv1 aggressive
    /// mode, one group per attempt, the next one if the gateway refuses it.
    private func group(_ id: UInt16) -> Binding<Bool> {
        Binding(get: { form.phase1DhGroups.contains(id) }, set: { on in
            var groups = form.phase1DhGroups.filter { $0 != id }
            if on { groups.append(id) }
            form.phase1DhGroups = groups.sorted { strength($0) > strength($1) }
        })
    }

    private func strength(_ id: UInt16) -> Int {
        dhStrength.firstIndex(of: id).map { dhStrength.count - $0 } ?? 0
    }

    var body: some View {
        LabeledContent("DH Groups") {
            LazyVGrid(columns: Array(repeating: GridItem(.fixed(56), alignment: .leading), count: 5),
                      alignment: .leading) {
                ForEach(offeredGroups(form), id: \.0) { id, name in
                    Toggle(String(id), isOn: group(id)).help(name)
                }
            }
        }
        if !form.legacyAlgorithms,
           form.phase1DhGroups.contains(legacyGroup) || form.pfsGroup == legacyGroup {
            Label("DH group 2 needs legacy algorithms allowed.", systemImage: "exclamationmark.triangle.fill")
                .font(.caption).foregroundStyle(.orange)
        }
    }
}

/// Switches the proposals between choices and free text.
private struct ProposalsAsTextToggle: View {
    @Binding var form: ProfileForm
    @State private var textError: String?

    private var asText: Binding<Bool> {
        Binding(get: { form.customProposals }, set: { on in
            textError = nil
            if on {
                do {
                    form = try proposalsAsText(form: form)
                } catch {
                    textError = describe(error)
                }
            } else {
                form = proposalsAsChoices(form: form)
                if form.customProposals {
                    textError = String(localized: "These proposals cannot be shown as choices.")
                }
            }
        })
    }

    var body: some View {
        Toggle("Edit the proposals as text", isOn: asText)
        if let textError {
            Text(verbatim: textError).font(.caption).foregroundStyle(.orange)
        } else {
            Text("For settings the choices above do not offer, in the syntax “aes256-sha256-modp2048”.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }
}

private func proposalText(_ title: LocalizedStringKey, _ binding: Binding<[String]>) -> some View {
    VStack(alignment: .leading, spacing: 4) {
        Text(title)
        TextEditor(text: lines(binding)).font(.system(.caption, design: .monospaced)).frame(minHeight: 44)
    }
}

/// "Paramètres avancés" of FortiClient: VPN settings, phase 1, phase 2.
private struct IpsecAdvancedTab: View {
    @Binding var form: ProfileForm

    /// FortiOS: AES-GCM in phase 1 with IKEv2 only, in phase 2 with both.
    private var isGcmAllowed: Bool { form.ikeVersion == 2 }

    private var kilobytes: Binding<Bool> {
        Binding(get: { form.phase2LifetimeKb != nil }, set: { form.phase2LifetimeKb = $0 ? 5120 : nil })
    }

    private var kilobyteValue: Binding<String> {
        Binding(get: { form.phase2LifetimeKb.map(String.init) ?? "" },
                set: { form.phase2LifetimeKb = UInt64($0.filter(\.isNumber).prefix(12)) ?? 0 })
    }

    private var pfs: Binding<Bool> {
        Binding(get: { form.pfsGroup != nil }, set: { form.pfsGroup = $0 ? lastPfsGroup : nil })
    }

    /// The PFS group, kept while PFS is off so the menu still shows it.
    @State private var lastPfsGroup: UInt16 = 14

    private var pfsGroup: Binding<UInt16> {
        Binding(get: { form.pfsGroup ?? lastPfsGroup }, set: {
            lastPfsGroup = $0
            form.pfsGroup = $0
        })
    }

    private var seconds: Binding<Bool> {
        Binding(get: { form.phase2Lifetime != 0 }, set: { form.phase2Lifetime = $0 ? 43200 : 0 })
    }

    var body: some View {
        Form {
            Section("VPN Settings") {
                Picker("IKE", selection: $form.ikeVersion) {
                    Text("Version 1").tag(UInt8(1))
                    Text("Version 2").tag(UInt8(2))
                }
                .pickerStyle(.radioGroup).horizontalRadioGroupLayout()
                if form.ikeVersion == 1 {
                    Picker("Mode", selection: $form.aggressiveMode) {
                        Text("Main").tag(false)
                        Text("Aggressive").tag(true)
                    }
                    .pickerStyle(.radioGroup).horizontalRadioGroupLayout()
                    if !form.aggressiveMode {
                        Text("Main mode protects the identities; the gateway chooses the tunnel before seeing the Local ID.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                LabeledContent("Options") { Text("Mode Config") }
                    .help("The gateway assigns the address, routes and DNS. Manual configuration is not supported yet.")
                TextField("Port", text: port($form.port))
                TextField("Local ID", text: optional($form.localId), prompt: Text("Optional"))
                TextField("Remote ID", text: optional($form.remoteId), prompt: Text("Optional"))
            }
            if form.customProposals {
                Section("Proposals") {
                    proposalText("IKE proposals (one per line)", $form.ikeProposals)
                    proposalText("ESP proposals (one per line)", $form.espProposals)
                }
            }
            Section("Phase 1") {
                if !form.customProposals {
                    SuiteRows(suites: $form.phase1Suites, gcm: isGcmAllowed, ikev2: form.ikeVersion == 2,
                              legacy: form.legacyAlgorithms, phase1: true)
                    DhGroupsRow(form: $form)
                }
                LabeledContent("Key Lifetime") {
                    HStack {
                        TextField("", text: number($form.phase1Lifetime)).labelsHidden().frame(width: 90)
                        Text("seconds")
                    }
                }
                Toggle("Dead peer detection", isOn: $form.dpd)
                if form.ikeVersion == 1 {
                    // Part of IKEv2 itself: FortiClient only shows it for IKEv1.
                    Toggle("NAT traversal", isOn: .constant(true)).disabled(true)
                        .help("Always on: ESP travels in UDP, so no kernel IPsec is needed.")
                }
            }
            Section("Phase 2") {
                if !form.customProposals {
                    SuiteRows(suites: $form.phase2Suites, gcm: true, ikev2: form.ikeVersion == 2,
                              legacy: form.legacyAlgorithms, phase1: false)
                }
                LabeledContent("Key Lifetime") {
                    VStack(alignment: .leading) {
                        HStack {
                            Toggle("", isOn: seconds).labelsHidden()
                            TextField("", text: number($form.phase2Lifetime)).labelsHidden().frame(width: 90)
                                .disabled(!seconds.wrappedValue)
                            Text("seconds")
                        }
                        HStack {
                            Toggle("", isOn: kilobytes).labelsHidden()
                            TextField("", text: kilobyteValue).labelsHidden().frame(width: 90).disabled(!kilobytes.wrappedValue)
                            Text("kilobytes")
                        }
                    }
                }
                if !form.customProposals {
                    Toggle("Perfect forward secrecy (PFS)", isOn: pfs)
                    Picker("DH Group", selection: pfsGroup) {
                        ForEach(offeredGroups(form), id: \.0) { id, name in Text(verbatim: "\(id) (\(name))").tag(id) }
                    }
                    .pickerStyle(.menu)
                    .disabled(form.pfsGroup == nil)
                }
            }
            Section {
                Toggle("Allow legacy algorithms (3DES, DH group 2)", isOn: $form.legacyAlgorithms)
                Text("Only for old gateways that offer nothing better: these algorithms are no longer considered secure.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section {
                ProposalsAsTextToggle(form: $form)
            }
        }
        .formStyle(.grouped)
        .onAppear { lastPfsGroup = form.pfsGroup ?? form.phase1DhGroups.first ?? 14 }
    }
}

/// L2TP over IPsec as System Settings shows it: the shared secret and
/// group name of IPsec, then the PPP user.
/// A WireGuard peer: our key pair (the private key in the Keychain), the
/// server's public key, the addresses and networks of `wg-quick`.
private struct WireGuardSections: View {
    @ObservedObject var editing: ProfileEditing
    @Binding var form: ProfileForm
    @Binding var advanced: Bool

    /// Ours: from the key being typed, else the one saved.
    private var publicKey: String? {
        let typed = editing.typedSecrets["private_key"] ?? ""
        return typed.isEmpty ? form.localPublicKey : wireguardPublicKey(privateKey: typed)
    }

    var body: some View {
        Section {
            SecretField(editing: editing, key: "private_key", label: "Private Key")
            LabeledContent("Public Key") {
                HStack {
                    if let publicKey {
                        Text(verbatim: publicKey).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                        Button {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(publicKey, forType: .string)
                        } label: {
                            Image(systemName: "doc.on.doc")
                        }
                        .buttonStyle(.borderless)
                        .help("Copy, for the server's administrator")
                    } else {
                        Text(editing.typedSecrets["private_key"]?.isEmpty == false ? "Not a WireGuard key" : "Unknown")
                            .foregroundStyle(.secondary)
                    }
                }
            }
            Button("Generate a New Key Pair") {
                editing.secret("private_key").wrappedValue = newWireguardPrivateKey()
            }
            .help("The server's administrator then declares the new public key.")
        }
        .onChange(of: editing.typedSecrets["private_key"]) { _, typed in
            if let typed, let key = wireguardPublicKey(privateKey: typed) { form.localPublicKey = key }
        }
        Section {
            TextField("Server Public Key", text: $form.peerPublicKey, prompt: Text(verbatim: "base64"))
                .font(.system(.body, design: .monospaced))
            Toggle("Pre-shared key", isOn: $form.presharedKey)
            if form.presharedKey {
                SecretField(editing: editing, key: "psk", label: "Pre-shared Key")
            }
        }
        Section {
            listEditor("Addresses in the tunnel (Address, one per line)", $form.addresses)
            listEditor("Networks of the server (AllowedIPs, one per line; 0.0.0.0/0 for everything)", $form.allowedIps)
            listEditor("DNS servers (one per line)", $form.dnsServers)
            listEditor("DNS search domains (one per line)", $form.dnsSearch)
        }
        Section {
            DisclosureGroup("Advanced Options", isExpanded: $advanced) {
                TextField("Port", text: port($form.port))
                TextField("Keepalive (seconds)", text: optionalNumber($form.persistentKeepalive), prompt: Text("Off"))
                    .help("Keeps NAT mappings open: 25 seconds is usual.")
                TextField("MTU", text: optionalNumber($form.mtu), prompt: Text(verbatim: "1420"))
            }
        }
    }

    private func listEditor(_ title: LocalizedStringKey, _ binding: Binding<[String]>) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
            TextEditor(text: lines(binding))
                .font(.system(.body, design: .monospaced))
                .frame(minHeight: 36)
        }
    }
}

/// An optional number as text; empty for none.
private func optionalNumber(_ binding: Binding<UInt16?>) -> Binding<String> {
    Binding(get: { binding.wrappedValue.map(String.init) ?? "" }, set: {
        let digits = $0.filter(\.isNumber)
        binding.wrappedValue = digits.isEmpty ? nil : UInt16(digits.prefix(5)).map { $0 }
    })
}

private struct L2tpSections: View {
    @ObservedObject var editing: ProfileEditing
    @Binding var form: ProfileForm
    @Binding var advanced: Bool

    var body: some View {
        Section {
            SecretField(editing: editing, key: "psk", label: "Pre-shared Key")
            TextField("Group Name", text: optional($form.localId), prompt: Text("Optional"))
                .help("The IKE identity; with one, phase 1 uses aggressive mode, as macOS does.")
        }
        Section {
            TextField("User Name", text: optional($form.username))
            Toggle("Save the password in the Keychain", isOn: $form.savePassword)
            if form.savePassword {
                SecretField(editing: editing, key: "password", label: "Password")
            }
        }
        Section {
            DisclosureGroup("Advanced Options", isExpanded: $advanced) {
                L2tpAdvancedOptions(form: $form)
            }
        }
    }
}

/// The IPsec proposals (IKEv1), PPP and DNS of an L2TP profile.
private struct L2tpAdvancedOptions: View {
    @Binding var form: ProfileForm

    var body: some View {
        TextField("Port", text: port($form.port))
        TextField("Remote ID", text: optional($form.remoteId), prompt: Text("Optional"))
        if form.customProposals {
            proposalText("IKE proposals (one per line)", $form.ikeProposals)
            proposalText("ESP proposals (one per line)", $form.espProposals)
        }
        Text("Phase 1").font(.headline)
        if !form.customProposals {
            // IKEv1: no AES-GCM in phase 1, no ChaCha20-Poly1305.
            SuiteRows(suites: $form.phase1Suites, gcm: false, ikev2: false, legacy: form.legacyAlgorithms, phase1: true)
            DhGroupsRow(form: $form)
        }
        LabeledContent("Key Lifetime") {
            HStack {
                TextField("", text: number($form.phase1Lifetime)).labelsHidden().frame(width: 90)
                Text("seconds")
            }
        }
        Text("Phase 2").font(.headline)
        if !form.customProposals {
            SuiteRows(suites: $form.phase2Suites, gcm: true, ikev2: false, legacy: form.legacyAlgorithms, phase1: false)
        }
        LabeledContent("Key Lifetime") {
            HStack {
                TextField("", text: number($form.phase2Lifetime)).labelsHidden().frame(width: 90)
                Text("seconds")
            }
        }
        Toggle("Allow legacy algorithms (3DES, DH group 2)", isOn: $form.legacyAlgorithms)
        Text("Only for old gateways that offer nothing better: these algorithms are no longer considered secure.")
            .font(.caption).foregroundStyle(.secondary)
        ProposalsAsTextToggle(form: $form)
        Toggle("Dead peer detection", isOn: $form.dpd)
        LabeledContent("PPP Authentication") {
            VStack(alignment: .leading) {
                Toggle(isOn: $form.pppMschapv2) { Text(verbatim: "MS-CHAPv2") }
                Toggle(isOn: $form.pppChap) { Text(verbatim: "CHAP") }
                Toggle(isOn: $form.pppPap) { Text(verbatim: "PAP") }
            }
        }
        if !form.pppMschapv2 && !form.pppChap && !form.pppPap {
            Label("Choose at least one authentication.", systemImage: "exclamationmark.triangle.fill")
                .font(.caption).foregroundStyle(.orange)
        }
        Text("PAP sends the password in clear inside IPsec and does not authenticate the server: turn it on only if the server asks for it (Meraki).")
            .font(.caption).foregroundStyle(.secondary)
        VStack(alignment: .leading, spacing: 4) {
            Text("DNS servers if the server assigns none (one per line, 4 at most)")
            TextEditor(text: lines($form.dnsServers)).font(.system(.caption, design: .monospaced)).frame(minHeight: 44)
        }
    }
}

/// Encryption / authentication pairs, like FortiClient's proposal rows.
private struct SuiteRows: View {
    @Binding var suites: [CipherSuite]
    /// AES-GCM allowed here.
    let gcm: Bool
    /// ChaCha20-Poly1305 has no IKEv1 identifier.
    let ikev2: Bool
    /// 3DES allowed.
    let legacy: Bool
    let phase1: Bool

    private func offered(_ encryption: String) -> Bool {
        if encryption.contains("gcm") { return gcm }
        if encryption == "chacha20poly1305" { return ikev2 }
        if encryption == "3des" { return legacy }
        return true
    }

    var body: some View {
        ForEach(suites.indices, id: \.self) { index in
            LabeledContent(index == 0 ? "Proposals" : "") {
                HStack {
                    Picker("Encryption", selection: $suites[index].encryption) {
                        // The current choice stays listed, with a warning below.
                        ForEach(encryptions.filter { offered($0.0) || $0.0 == suites[index].encryption }, id: \.0) {
                            Text(verbatim: $0.1).tag($0.0)
                        }
                    }
                    let aead = isAead(suites[index].encryption)
                    if !aead || phase1 {
                        Picker(aead ? "PRF" : "Authentication", selection: $suites[index].hash) {
                            ForEach(hashes, id: \.0) { Text(verbatim: $0.1).tag($0.0) }
                        }
                    }
                    Button {
                        suites.remove(at: index)
                    } label: {
                        Image(systemName: "minus.circle")
                    }
                    .buttonStyle(.borderless)
                    .disabled(suites.count == 1)
                    .help("Remove")
                }
            }
        }
        if !gcm, suites.contains(where: { $0.encryption.contains("gcm") }) {
            Label("AES-GCM in phase 1 needs IKEv2.", systemImage: "exclamationmark.triangle.fill")
                .font(.caption).foregroundStyle(.orange)
        }
        if !ikev2, suites.contains(where: { $0.encryption == "chacha20poly1305" }) {
            Label("ChaCha20-Poly1305 needs IKEv2.", systemImage: "exclamationmark.triangle.fill")
                .font(.caption).foregroundStyle(.orange)
        }
        if !legacy, suites.contains(where: { $0.encryption == "3des" }) {
            Label("3DES needs legacy algorithms allowed.", systemImage: "exclamationmark.triangle.fill")
                .font(.caption).foregroundStyle(.orange)
        }
        Button {
            suites.append(suites.last ?? CipherSuite(encryption: "aes256", hash: "sha256"))
        } label: {
            Label("Add a Proposal", systemImage: "plus.circle")
        }
        .buttonStyle(.borderless)
        .disabled(suites.count >= 6)
    }
}

private struct NetworkTab: View {
    @Binding var form: ProfileForm
    /// The other VPNs (id, name), to chain through.
    let others: [(String, String)]

    /// Ticked VPNs keep the order they were ticked in: the first is the
    /// one brought up when none is.
    private func through(_ id: String) -> Binding<Bool> {
        Binding(get: { form.via.contains(id) }, set: { on in
            form.via.removeAll { $0 == id }
            if on { form.via.append(id) }
        })
    }

    private func name(_ id: String) -> String { others.first { $0.0 == id }?.1 ?? id }

    private var ownRoutes: Binding<Bool> {
        Binding(get: { form.routes != nil }, set: { form.routes = $0 ? (form.routes ?? []) : nil })
    }

    private var routes: Binding<[ListEntry]> {
        Binding(get: { form.routes ?? [] }, set: { form.routes = $0 })
    }

    var body: some View {
        Form {
            Picker("Traffic", selection: $form.tunnelMode) {
                Text("As the gateway decides").tag(TunnelMode.automatic)
                Text("Everything through the VPN").tag(TunnelMode.full)
                Text("Only the VPN's networks").tag(TunnelMode.split)
            }
            if form.kind == .openVpn {
                VStack(alignment: .leading, spacing: 4) {
                    NotedList(title: "Additional networks through the VPN", entries: $form.extraRoutes, kind: .network)
                    Text("Added to the networks the server announces, like the route lines of an OpenVPN file.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            Toggle("Use my own networks instead of the gateway's", isOn: ownRoutes)
            if form.routes != nil {
                NotedList(title: "Networks", entries: routes, kind: .network)
            }
            VStack(alignment: .leading, spacing: 4) {
                NotedList(title: "Networks in split mode", entries: $form.splitRoutes, kind: .network)
                Text("The menu then also offers to connect this VPN in split mode: only these networks go through it, the rest of the traffic does not. Add the DNS domains below, or the VPN's DNS servers are not used.")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Text("A network list may also hold domains (*.corp-saas.com for every name under it): their addresses go through the VPN as they are resolved.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if form.tunnelMode != .split {
                VStack(alignment: .leading, spacing: 4) {
                    NotedList(title: "Outside the VPN", entries: $form.excludedDomains, kind: .pattern)
                    Text("When the VPN takes all traffic: the names under these domains are resolved by the DNS in place before the VPN, and their addresses reached directly (video calls, say). Public addresses only.")
                        .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
            }
            NotedList(title: "DNS domains resolved through this VPN", entries: $form.dnsDomains, kind: .domain)
            if !others.isEmpty {
                Section("Connect Through") {
                    ForEach(others, id: \.0) { id, name in
                        Toggle(isOn: through(id)) {
                            if let i = form.via.firstIndex(of: id) {
                                Text(verbatim: "\(i + 1). \(name)")
                            } else {
                                Text(verbatim: name)
                            }
                        }
                    }
                    Text(form.via.isEmpty
                         ? "Chain this VPN through others: it then goes through whichever is up, or brings up the first one before itself."
                         : "Connected normally, this VPN goes through the first of these that is up, or brings up \(name(form.via[0])) first; its networks may overlap theirs. The menu also offers to connect it directly.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            Toggle("Allow networks that overlap another VPN's", isOn: $form.allowRouteOverlap)
            Text("Without it, a VPN that would take traffic from another one is not connected.")
                .font(.caption).foregroundStyle(.secondary)
            Toggle("Company VPN: never at the same time as another VPN", isOn: $form.exclusive)
            Text("Before it connects, the other VPNs are disconnected, after asking you. While it is up, the others wait.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .formStyle(.grouped)
    }
}

