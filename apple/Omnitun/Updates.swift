// Updates with Sparkle: the latest GitHub Release's appcast.xml, checked
// daily; a new version is offered, installed (the .pkg, administrator
// password asked) only when the user accepts.

import AppKit
import OSLog
import Sparkle

@MainActor
final class Updates: NSObject, SPUStandardUserDriverDelegate, SPUUpdaterDelegate {
    static let shared = Updates()
    private var controller: SPUStandardUpdaterController?
    /// Called just before the installer stops the service and the app.
    var willInstall: (() -> Void)?

    /// A build run from the package's .app: `swift run` has no bundle, no
    /// feed and no key to check against.
    private var installed: Bool {
        Bundle.main.bundlePath.hasSuffix(".app") && Bundle.main.object(forInfoDictionaryKey: "SUPublicEDKey") != nil
    }

    func start() {
        guard installed, controller == nil else { return }
        controller = SPUStandardUpdaterController(startingUpdater: true, updaterDelegate: self, userDriverDelegate: self)
    }

    var available: Bool { controller != nil }

    func checkNow() {
        controller?.checkForUpdates(nil)
    }

    var checksAutomatically: Bool {
        get { controller?.updater.automaticallyChecksForUpdates ?? false }
        set { controller?.updater.automaticallyChecksForUpdates = newValue }
    }

    // A menu bar app has no window to come forward: Sparkle shows its
    // reminder discreetly, and brings its window to the front when the user
    // asks.
    nonisolated var supportsGentleScheduledUpdateReminders: Bool { true }

    private static let log = Logger(subsystem: Bundle.main.bundleIdentifier ?? "Omnitun", category: "updates")

    // The package's installer starts once the administrator password is
    // given. When that dialog closes, macOS gives the focus back to the app
    // active before, never to a menu bar app, and refuses it to us: the
    // window that then offers to install and relaunch would stay behind.
    // It floats above the other apps' windows until it closes.
    // The VPNs up now come back after the update: quitting for it must not
    // disconnect them first.
    nonisolated func updater(_ updater: SPUUpdater, willInstallUpdate item: SUAppcastItem) {
        MainActor.assumeIsolated {
            Settings.relaunching = true
            willInstall?()
        }
    }

    nonisolated func updater(_ updater: SPUUpdater, didExtractUpdate item: SUAppcastItem) {
        MainActor.assumeIsolated {
            let sparkle = Bundle(for: SPUStandardUpdaterController.self)
            let windows = NSApp.windows.filter { window in
                window.isVisible && window.windowController.map { Bundle(for: type(of: $0)) == sparkle } == true
            }
            Self.log.notice("installer started for \(item.displayVersionString, privacy: .public): \(windows.count) window(s) kept in front")
            for window in windows {
                window.level = .floating
                window.orderFrontRegardless()
            }
            NSApp.activate()
        }
    }
}
