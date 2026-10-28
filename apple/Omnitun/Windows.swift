import AppKit
import SwiftUI
import UniformTypeIdentifiers
import VPNClientCore

/// Small floating windows for the menu bar app. A menu closes at the first
/// click elsewhere, so every question gets its own window.
final class Panel: NSPanel, NSWindowDelegate {
    /// Called when the user closes the window (not when the app does).
    var onUserClose: (() -> Void)?

    init<Content: View>(title: String, content: Content) {
        super.init(
            contentRect: .zero, styleMask: [.titled, .closable], backing: .buffered, defer: false)
        self.title = title
        contentViewController = NSHostingController(rootView: content)
        isReleasedWhenClosed = false
        hidesOnDeactivate = false
        level = .floating
        delegate = self
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        onUserClose?()
        onUserClose = nil
        return true
    }

    func present() {
        center()
        bringForward(self)
    }
}

/// Shows `window` in front, on the current Space. An accessory app's
/// activation can be refused (macOS 14 cooperative activation, a click in
/// the menu bar while another app is active): the window then still comes
/// in front, without the focus, instead of opening behind the other app.
@MainActor
func bringForward(_ window: NSWindow) {
    window.collectionBehavior.insert(.moveToActiveSpace)
    if window.isMiniaturized { window.deminiaturize(nil) }
    NSApp.activate()
    window.makeKeyAndOrderFront(nil)
    window.orderFrontRegardless()
}

/// Asks the window's content before it closes (unsaved changes).
private final class CloseGuard: NSObject, NSWindowDelegate {
    let shouldClose: () -> Bool

    init(_ shouldClose: @escaping () -> Bool) {
        self.shouldClose = shouldClose
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        MainActor.assumeIsolated { shouldClose() }
    }
}

@MainActor
final class Windows {
    static let shared = Windows()
    private var named: [String: NSWindow] = [:]
    /// The settings window's tab, so that an open window can be switched.
    private let settingsTab = SettingsView.Selection()
    private var guards: [String: CloseGuard] = [:]

    /// One window per kind (settings, welcome, import), brought forward if open.
    func show<Content: View>(_ key: String, title: String, resizable: Bool = false,
                             shouldClose: (() -> Bool)? = nil, content: () -> Content) {
        // A minimized window is not visible, but still open.
        if let window = named[key], window.isVisible || window.isMiniaturized {
            bringForward(window)
            return
        }
        let window = NSWindow(contentViewController: NSHostingController(rootView: content()))
        window.title = title
        window.styleMask = resizable ? [.titled, .closable, .resizable] : [.titled, .closable]
        window.isReleasedWhenClosed = false
        window.center()
        guards[key] = shouldClose.map(CloseGuard.init)
        window.delegate = guards[key]
        named[key] = window
        bringForward(window)
    }

    func close(_ key: String) {
        named[key]?.close()
    }

    func showWelcome(model: AppModel) {
        show("welcome", title: String(localized: "Welcome to \(brand.product)")) { WelcomeView(model: model) }
    }

    /// `tab`: the one to show; nil opens on General, or keeps the tab of a
    /// window already open.
    func showSettings(model: AppModel, tab: SettingsView.Tab? = nil) {
        let open = named["settings"].map { $0.isVisible || $0.isMiniaturized } ?? false
        if let tab {
            settingsTab.tab = tab
        } else if !open {
            settingsTab.tab = .general
        }
        show("settings", title: String(localized: "Settings")) { SettingsView(model: model, selection: settingsTab) }
    }

    /// `profile`: shown in the editor, when the window opens.
    func showManage(model: AppModel, profile: String? = nil) {
        let editing = ProfileEditing(model: model)
        if let profile { editing.select(profile) }
        show("manage", title: String(localized: "Manage VPNs"), resizable: true, shouldClose: editing.shouldClose) {
            ManageView(model: model, editing: editing)
        }
    }

    /// A .vpnprofile file to add, after the user checked it.
    func showReceived(model: AppModel, url: URL) {
        let received: ReceivedProfile
        do {
            received = try model.client.readVpnprofile(path: url.path)
        } catch {
            alert(String(localized: "This VPN profile cannot be used"), describe(error))
            return
        }
        let holder = WindowHolder()
        let panel = Panel(title: String(localized: "New VPN"), content: ReceivedView(
            model: model, fileName: url.lastPathComponent, received: received) { holder.window?.close() })
        holder.window = panel
        panel.present()
    }

    func showImport(model: AppModel) {
        show("import", title: String(localized: "Import from FortiClient")) { ImportView(model: model) }
    }

    func showMacImport(model: AppModel) {
        show(ImportSource.macOS.window, title: String(localized: "Import from System Settings")) {
            ImportView(model: model, sources: [.macOS])
        }
    }

    func showViscosityImport(model: AppModel) {
        show(ImportSource.viscosity.window, title: String(localized: "Import from Viscosity")) {
            ImportView(model: model, sources: [.viscosity])
        }
    }

    static let setupKey = "setup"

    /// The first-launch assistant: what other VPN apps of this Mac hold,
    /// offered while the user has no VPN yet.
    func showSetup(model: AppModel) {
        Settings.offeredImport = true
        show(Self.setupKey, title: String(localized: "Welcome to \(brand.product)")) {
            ImportView(model: model, sources: [.fortiClient, .viscosity, .macOS], setup: true)
        }
    }

    /// An OpenVPN or WireGuard configuration the user picks, converted,
    /// then shown with what the import left out before it is added.
    func importOpenVpn(model: AppModel) {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = ["ovpn", "conf"].compactMap { UTType(filenameExtension: $0) }
        panel.allowsMultipleSelection = false
        NSApp.activate()
        guard panel.runModal() == .OK, let url = panel.url else { return }
        importFile(model: model, url: url)
    }

    /// An OpenVPN or WireGuard configuration, picked or opened from the
    /// Finder.
    func importFile(model: AppModel, url: URL) {
        let wireGuard = isWireguardConfig(path: url.path)
        let imported: ImportedProfile
        do {
            if wireGuard {
                imported = try model.client.importWireguard(path: url.path)
            } else {
                guard let first = try model.client.importOpenvpn(path: url.path).first else { return }
                imported = first
            }
        } catch {
            alert(wireGuard ? String(localized: "This WireGuard file cannot be imported")
                            : String(localized: "This OpenVPN file cannot be imported"), describe(error))
            return
        }
        let holder = WindowHolder()
        let title = wireGuard ? String(localized: "Import WireGuard File") : String(localized: "Import OpenVPN File")
        let window = Panel(title: title, content: OpenVpnImportView(
            model: model, fileName: url.lastPathComponent, imported: imported,
            wireGuard: wireGuard ? url : nil) { holder.window?.close() })
        holder.window = window
        window.present()
    }

    /// `profile`: the profile's id.
    func showCertificateChanged(model: AppModel, profile: String, failure: FailureInfo) {
        guard let presented = failure.certificate else { return }
        if let open = named["certificate-\(profile)"], open.isVisible || open.isMiniaturized {
            bringForward(open)
            return
        }
        let holder = WindowHolder()
        let name = model.displayName(profile)
        let panel = Panel(
            title: name,
            content: CertificateChangedView(
                profile: name, presented: presented, pinned: failure.pinned,
                close: { holder.window?.close() },
                confirmed: {
                    holder.window?.close()
                    self.showReplaceCertificate(model: model, profile: profile, presented: presented)
                }))
        holder.window = panel
        panel.present()
        named["certificate-\(profile)"] = panel
    }

    /// Trusting a new certificate after a change: typed fingerprint start,
    /// then the user's authentication (decision 7 of the plan).
    func showReplaceCertificate(model: AppModel, profile: String, presented: Certificate) {
        let holder = WindowHolder()
        let panel = Panel(
            title: model.displayName(profile),
            content: ReplaceCertificateView(model: model, profile: profile, presented: presented) {
                holder.window?.close()
            })
        holder.window = panel
        panel.present()
    }

    func alert(_ title: String, _ message: String) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        NSApp.activate()
        alert.runModal()
    }
}

/// The questions of a connection, each in its own panel; the reply closure
/// is called exactly once (closing the window cancels).
@MainActor
enum Prompts {
    struct Answer {
        var value: String
        var remember: Bool
    }

    /// `canRemember`: the profile lets passwords be kept in the Keychain.
    static func ask(profile: String, prompt: Prompt, canRemember: Bool = true,
                    reply: @escaping (Answer?) -> Void) -> NSWindow {
        let once = Once(reply)
        let panel: Panel
        switch prompt.kind {
        case .otp:
            panel = Panel(title: profile, content: CodePromptView(profile: profile, prompt: prompt) { once($0) })
        case .secret:
            panel = Panel(title: profile, content: SecretPromptView(
                profile: profile, prompt: prompt, canRemember: canRemember) { once($0) })
        case .text, .confirm:
            panel = Panel(title: profile, content: TextPromptView(profile: profile, prompt: prompt) { once($0) })
        }
        panel.onUserClose = { once(nil) }
        once.after = { [weak panel] answer in
            // A push approval keeps its window open until the gateway answers.
            if !(prompt.push && answer?.value.isEmpty == true) { panel?.close() }
        }
        panel.present()
        return panel
    }

    static func trust(profile: String, certificate: Certificate, reply: @escaping (TrustDecision) -> Void) -> NSWindow {
        let once = Once<TrustDecision>(reply)
        let panel = Panel(title: profile, content: TrustView(profile: profile, certificate: certificate) { once($0) })
        panel.onUserClose = { once(.reject) }
        once.after = { [weak panel] _ in panel?.close() }
        panel.present()
        return panel
    }

    static func browser(profile: String, url: URL, cancel: @escaping () -> Void) -> NSWindow {
        let panel = Panel(title: profile, content: BrowserView(profile: profile, url: url, cancel: cancel))
        panel.onUserClose = cancel
        panel.present()
        return panel
    }
}

/// Calls its closure once, then `after`.
@MainActor
final class Once<Value> {
    private var reply: ((Value) -> Void)?
    var after: ((Value) -> Void)?

    init(_ reply: @escaping (Value) -> Void) { self.reply = reply }

    func callAsFunction(_ value: Value) {
        guard let reply else { return }
        self.reply = nil
        reply(value)
        after?(value)
    }
}

/// Lets a view close the window it is shown in.
@MainActor
final class WindowHolder {
    weak var window: NSWindow?
}
