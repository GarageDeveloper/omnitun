// Updates with Sparkle: the latest GitHub Release's appcast.xml, checked
// daily; a new version is offered, installed (the .pkg, administrator
// password asked) only when the user accepts.

import Sparkle

@MainActor
final class Updates: NSObject, SPUStandardUserDriverDelegate {
    static let shared = Updates()
    private var controller: SPUStandardUpdaterController?

    /// A build run from the package's .app: `swift run` has no bundle, no
    /// feed and no key to check against.
    private var installed: Bool {
        Bundle.main.bundlePath.hasSuffix(".app") && Bundle.main.object(forInfoDictionaryKey: "SUPublicEDKey") != nil
    }

    func start() {
        guard installed, controller == nil else { return }
        controller = SPUStandardUpdaterController(startingUpdater: true, updaterDelegate: nil, userDriverDelegate: self)
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
}
