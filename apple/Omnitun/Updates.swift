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

    // The package's installer asks for an administrator password before it
    // extracts the update. When that dialog closes, macOS gives the focus
    // back to the app active before, never to a menu bar app: Sparkle's
    // window (ready to install) would stay behind the others.
    nonisolated func updater(_ updater: SPUUpdater, didExtractUpdate item: SUAppcastItem) {
        MainActor.assumeIsolated {
            Self.log.info("update \(item.displayVersionString, privacy: .public) extracted: bringing its window forward")
            NSApp.activate()
            for window in NSApp.windows where window.isVisible && window.canBecomeKey {
                window.orderFrontRegardless()
                window.makeKey()
            }
        }
    }
}
