// Menu bar app: an NSStatusItem menu for everyday use, small SwiftUI
// windows for prompts, welcome, settings and import. The VPN logic lives
// in Rust (VPNClientCore); this layer only shows and asks.

import AppKit
import SwiftUI
import VPNClientCore

let brand = VPNClientCore.brand()

@main
enum Main {
    @MainActor static func main() {
        let app = NSApplication.shared
        let delegate = AppDelegate()
        app.delegate = delegate
        app.setActivationPolicy(.accessory)
        app.mainMenu = editMenu()
        app.run()
    }
}

/// A menu bar app has no menu bar of its own, so ⌘V, ⌘C… find no command
/// unless a main menu provides them; it stays invisible.
@MainActor
func editMenu() -> NSMenu {
    let edit = NSMenu(title: String(localized: "Edit"))
    edit.addItem(withTitle: String(localized: "Undo"), action: Selector(("undo:")), keyEquivalent: "z")
    edit.addItem(withTitle: String(localized: "Redo"), action: Selector(("redo:")), keyEquivalent: "Z")
    edit.addItem(.separator())
    edit.addItem(withTitle: String(localized: "Cut"), action: #selector(NSText.cut(_:)), keyEquivalent: "x")
    edit.addItem(withTitle: String(localized: "Copy"), action: #selector(NSText.copy(_:)), keyEquivalent: "c")
    edit.addItem(withTitle: String(localized: "Paste"), action: #selector(NSText.paste(_:)), keyEquivalent: "v")
    edit.addItem(withTitle: String(localized: "Select All"), action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
    let close = NSMenu(title: String(localized: "Window"))
    close.addItem(withTitle: String(localized: "Close"), action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
    let main = NSMenu()
    for menu in [NSMenu(title: brand.product), edit, close] {
        let item = NSMenuItem()
        item.submenu = menu
        main.addItem(item)
    }
    return main
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var model: AppModel!
    private var statusMenu: StatusMenu!
    /// Profile files opened before the app finished launching.
    private var pendingFiles: [URL] = []

    /// .vpnprofile and .ovpn files opened from the Finder or Mail.
    func application(_ application: NSApplication, open urls: [URL]) {
        let files = urls.filter { ["vpnprofile", "ovpn"].contains($0.pathExtension.lowercased()) }
        guard let model else {
            pendingFiles += files
            return
        }
        for url in files { open(url, model: model) }
    }

    private func open(_ url: URL, model: AppModel) {
        if url.pathExtension.lowercased() == "vpnprofile" {
            Windows.shared.showReceived(model: model, url: url)
        } else {
            Windows.shared.importFile(model: model, url: url)
        }
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        do {
            model = try AppModel()
        } catch {
            let alert = NSAlert()
            alert.messageText = String(localized: "\(brand.product) cannot start")
            alert.informativeText = describe(error)
            alert.runModal()
            NSApp.terminate(nil)
            return
        }
        statusMenu = StatusMenu(model: model)
        model.start()
        Updates.shared.start()
        for url in pendingFiles { open(url, model: model) }
        pendingFiles = []
        if !Settings.welcomed {
            Windows.shared.showWelcome(model: model)
        } else if model.profiles.isEmpty && model.profilesError == nil && !Settings.offeredImport {
            Windows.shared.showSetup(model: model)
        }
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let model, Settings.disconnectOnQuit, !Settings.relaunching, !model.sessions.isEmpty else {
            return .terminateNow
        }
        // Without the app, a code or a browser login cannot be asked again.
        Task {
            await model.disconnectAll(timeout: 10)
            NSApp.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }
}

/// User preferences (Settings window).
enum Settings {
    private static let defaults = UserDefaults.standard

    /// Folders made in Manage VPNs before any VPN is filed in them.
    static var emptyFolders: [String] {
        get { defaults.stringArray(forKey: "emptyFolders") ?? [] }
        set { defaults.set(newValue, forKey: "emptyFolders") }
    }

    static var welcomed: Bool {
        get { defaults.bool(forKey: "welcomed") }
        set { defaults.set(newValue, forKey: "welcomed") }
    }

    /// The import assistant was shown once: later, imports are in Manage
    /// VPNs.
    static var offeredImport: Bool {
        get { defaults.bool(forKey: "offeredImport") }
        set { defaults.set(newValue, forKey: "offeredImport") }
    }

    static var disconnectOnQuit: Bool {
        get { defaults.object(forKey: "disconnectOnQuit") as? Bool ?? true }
        set { defaults.set(newValue, forKey: "disconnectOnQuit") }
    }

    static var notifyConnected: Bool {
        get { defaults.bool(forKey: "notifyConnected") }
        set { defaults.set(newValue, forKey: "notifyConnected") }
    }

    static var notifyFailures: Bool {
        get { defaults.object(forKey: "notifyFailures") as? Bool ?? true }
        set { defaults.set(newValue, forKey: "notifyFailures") }
    }

    enum Language: String {
        case system
        case english = "en"
        case french = "fr"
    }

    /// The app's language over the one macOS chose; applied at the next
    /// launch through the app's own AppleLanguages.
    static var language: Language {
        get { Language(rawValue: defaults.string(forKey: "language") ?? "") ?? .system }
        set {
            defaults.set(newValue.rawValue, forKey: "language")
            if newValue == .system {
                defaults.removeObject(forKey: "AppleLanguages")
            } else {
                defaults.set([newValue.rawValue], forKey: "AppleLanguages")
            }
        }
    }

    /// Set while restarting the app, which must not disconnect the VPNs.
    @MainActor static var relaunching = false
}

/// Quits and opens the app again (for a language change); the VPNs run in
/// the service and stay up.
@MainActor
func relaunch() {
    Settings.relaunching = true
    let shell = Process()
    shell.executableURL = URL(fileURLWithPath: "/bin/sh")
    shell.arguments = ["-c", "sleep 1; /usr/bin/open \"$0\"", Bundle.main.bundlePath]
    try? shell.run()
    NSApp.terminate(nil)
}

func describe(_ error: Error) -> String {
    if case let ClientError.Failed(_, message) = error { return message }
    return error.localizedDescription
}
