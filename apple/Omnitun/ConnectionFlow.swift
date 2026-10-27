import AppKit
import VPNClientCore

/// One connection being set up: answers the daemon's questions through
/// small windows, opens the browser for SAML, and stores the secrets the
/// user chose to remember once the connection succeeded.
final class ConnectionFlow: ConnectionDelegate, @unchecked Sendable {
    enum Phase: Equatable {
        case starting
        case asking
        case browser(URL)
        /// Waiting for an approval on the phone.
        case push
    }

    /// The profile's id.
    let profile: String
    /// Without the VPNs the profile is chained through.
    let direct: Bool
    /// Only the profile's split-mode networks through the VPN.
    let split: Bool
    private weak var model: AppModel?
    // Main thread only, like everything below.
    private var connection: Connection?
    private var client: Client?
    private var remembered: [(profile: String, key: String, value: String)] = []
    /// The profile being connected now: this one, or a VPN it goes
    /// through (ids), and its name.
    private(set) var current: String
    private var currentName: String {
        MainActor.assumeIsolated { model?.displayName(current) ?? current }
    }
    private var windows: [NSWindow] = []
    private(set) var phase: Phase = .starting {
        didSet { MainActor.assumeIsolated { model?.flowChanged() } }
    }

    @MainActor
    init(profile: String, direct: Bool = false, split: Bool = false, model: AppModel) {
        self.profile = profile
        self.current = profile
        self.direct = direct
        self.split = split
        self.model = model
    }

    @MainActor
    func start(client: Client) {
        self.client = client
        connection = client.connect(id: profile, direct: direct, split: split, delegate: self)
    }

    /// Gives up: the daemon drops the attempt once its client is gone; the
    /// disconnect clears the failed session it would otherwise list.
    @MainActor
    func cancel() {
        connection?.cancel()
        closeWindows()
        let (client, profile) = (client, profile)
        Task { try? await client?.disconnect(id: profile) }
        model?.flowFinished(self, error: nil)
    }

    /// What the row of `id` shows: the VPN being brought up shows the
    /// steps, the chained one waits for it.
    @MainActor
    func status(for id: String) -> String {
        if id != current {
            return String(localized: "Connecting \(currentName) first…")
        }
        return switch phase {
        case .starting: String(localized: "Connecting…")
        case .asking: String(localized: "Waiting for your input")
        case .browser: String(localized: "Connecting… finish in your browser")
        case .push: String(localized: "Approve on your phone")
        }
    }

    // MARK: ConnectionDelegate (called on a Rust thread)

    func prompt(id: UInt64, prompt: Prompt) {
        onMain { flow in
            flow.phase = .asking
            let current = flow.current
            // The Keychain keeps only these, whatever key the engine asks.
            let canRemember = (flow.model?.profile(current)?.savePassword ?? true)
                && ["password", "psk", "private_key"].contains(prompt.key)
            let window = Prompts.ask(profile: flow.currentName, prompt: prompt, canRemember: canRemember) {
                [weak flow] answer in
                guard let flow else { return }
                flow.connection?.answer(id: id, value: answer?.value)
                guard let answer else { return }
                if answer.remember { flow.remembered.append((current, prompt.key, answer.value)) }
                flow.phase = prompt.push && answer.value.isEmpty ? .push : .starting
            }
            flow.track(window)
        }
    }

    func trustCertificate(id: UInt64, certificate: Certificate) {
        onMain { flow in
            flow.phase = .asking
            let window = Prompts.trust(profile: flow.currentName, certificate: certificate) { [weak flow] decision in
                flow?.connection?.trust(id: id, decision: decision)
                flow?.phase = .starting
            }
            flow.track(window)
        }
    }

    func openUrl(url: String) {
        onMain { flow in
            guard let url = URL(string: url) else { return }
            NSWorkspace.shared.open(url)
            flow.phase = .browser(url)
            let window = Prompts.browser(profile: flow.currentName, url: url) { [weak flow] in
                MainActor.assumeIsolated { flow?.cancel() }
            }
            flow.track(window)
        }
    }

    func notice(notice: Notice) {
        onMain { flow in
            switch notice {
            case .state(.connected, _, _):
                flow.closeWindows()
            case let .connecting(id, _):
                flow.current = id
                flow.phase = .starting
                flow.model?.flowReached(flow, profile: id)
            case let .urlRefused(url):
                Windows.shared.alert(
                    String(localized: "\(flow.currentName): login page refused"),
                    String(localized: "The gateway asks to open \(url), which is not on the profile's server."))
            default:
                break
            }
        }
    }

    func finished(error: ClientError?) {
        onMain { flow in
            flow.closeWindows()
            if error == nil { flow.saveRemembered() }
            flow.remembered = []
            flow.model?.flowFinished(flow, error: error)
        }
    }

    // MARK: Helpers

    private func onMain(_ body: @escaping @MainActor (ConnectionFlow) -> Void) {
        DispatchQueue.main.async { MainActor.assumeIsolated { body(self) } }
    }

    @MainActor private func track(_ window: NSWindow?) {
        if let window { windows.append(window) }
    }

    @MainActor private func closeWindows() {
        windows.forEach { $0.close() }
        windows = []
    }

    /// Only once the server accepted them, so a typo is never stored.
    @MainActor private func saveRemembered() {
        for secret in remembered {
            do {
                try client?.setSecret(id: secret.profile, key: secret.key, value: secret.value)
            } catch {
                Windows.shared.alert(String(localized: "Cannot save to the Keychain"), describe(error))
            }
        }
        if !remembered.isEmpty { model?.secretsDidChange() }
    }
}
