import AppKit
import Combine
import VPNClientCore

/// What the menu and windows show: profiles, the daemon's sessions, the
/// connections being set up, and the state of the service.
@MainActor
final class AppModel: ObservableObject {
    enum Service: Equatable {
        case checking
        case running(ServiceInfo)
        case unavailable(String)
    }

    let client: Client
    @Published private(set) var profiles: [ProfileSummary] = []
    @Published private(set) var profilesError: String?
    @Published private(set) var sessions: [String: Session] = [:]
    @Published private(set) var service: Service = .checking
    // Everything below is keyed by profile id; names are for people only.

    /// Connections waiting for the user or the gateway, by profile.
    @Published private(set) var flows: [String: ConnectionFlow] = [:]
    /// Failures that left no session behind, by profile.
    @Published private(set) var failures: [String: String] = [:]
    /// Latest reconnection attempt, by profile.
    @Published private(set) var retries: [String: Retry] = [:]
    /// How each profile was last connected: tried again the same way.
    private var lastOptions: [String: (direct: Bool, split: Bool)] = [:]
    /// Bumped when secrets change outside the editor (remembered at a
    /// connection, typed at an import, forgotten after a refusal).
    @Published private(set) var secretsChanged = 0
    /// Profiles an import just added, for the editor to show.
    @Published var imported: [String] = []

    func secretsDidChange() { secretsChanged += 1 }

    private var subscription: VPNClientCore.Subscription?
    private var watchRetry: Task<Void, Never>?

    init() throws {
        client = try Client(configPath: nil)
        nameOf = { [weak self] id in self?.displayName(id) ?? id }
    }

    /// The name people know `id` by: its profile's, or its session's if
    /// the profile is gone.
    func displayName(_ id: String) -> String {
        profiles.first { $0.id == id }?.name ?? sessions[id]?.name ?? id
    }

    func profile(_ id: String) -> ProfileSummary? { profiles.first { $0.id == id } }

    func start() {
        Notifier.shared.setUp()
        reloadProfiles()
        watch()
    }

    func reloadProfiles() {
        do {
            profiles = try client.profiles()
            profilesError = nil
        } catch {
            profilesError = describe(error)
        }
    }

    /// Profile ids first, then active sessions whose profile is gone (a
    /// deleted profile's ended session is not shown).
    var ids: [String] {
        let known = profiles.map(\.id)
        let orphans = sessions.filter { !known.contains($0.key) && ![.disconnected, .failed].contains($0.value.state) }
        return known + orphans.values.sorted { $0.name < $1.name }.map(\.id)
    }

    /// Drops what is known of `id`'s ended session, here and in the
    /// service, once its profile is deleted.
    func forget(_ id: String) {
        failures[id] = nil
        guard sessions[id] != nil else { return }
        sessions[id] = nil
        Task { try? await client.disconnect(id: id) }
    }

    var connectedCount: Int { sessions.values.filter { $0.state == .connected }.count }

    var isBusy: Bool {
        !flows.isEmpty || sessions.values.contains { [.connecting, .reconnecting, .disconnecting].contains($0.state) }
    }

    var hasProblem: Bool {
        if case .unavailable = service { return true }
        return !failures.isEmpty || sessions.values.contains { $0.state == .failed }
    }

    /// Connected in split mode: its split-mode networks, not all traffic.
    func isSplit(_ id: String) -> Bool {
        guard let session = sessions[id], !session.fullTunnel,
              let networks = profile(id)?.splitRoutes, !networks.isEmpty else { return false }
        return Set(session.routes).isSuperset(of: networks.map(\.value))
    }

    func isOn(_ id: String) -> Bool {
        if flows[id] != nil { return true }
        guard let s = sessions[id] else { return false }
        return s.state != .failed && s.state != .disconnected && s.state != .disconnecting
    }

    // MARK: Service and sessions

    func refreshService() {
        Task {
            do {
                service = .running(try await client.serviceInfo())
            } catch {
                service = .unavailable(describe(error))
            }
        }
    }

    private func watch() {
        watchRetry?.cancel()
        subscription = client.watch(observer: Observer(model: self))
        refreshService()
    }

    /// Fresh counters and durations (state changes come by the watch).
    func pollSessions() {
        Task {
            guard let list = try? await client.sessions() else { return }
            received(list)
        }
    }

    fileprivate func received(_ list: [Session]) {
        sessions = Dictionary(list.map { ($0.id, $0) }, uniquingKeysWith: { _, new in new })
        for session in list {
            if let announced = session.announced {
                let since = session.connectedSince.map { Date(timeIntervalSince1970: TimeInterval($0)) } ?? Date()
                Settings.remember(announced, for: session.id, at: since)
            }
        }
        for id in retries.keys where sessions[id]?.state != .reconnecting {
            retries[id] = nil
        }
        if case .running = service {} else { refreshService() }
    }

    fileprivate func changed(_ change: StateChange) {
        retries[change.id] = change.retry
        if change.state == .connecting || change.state == .connected { failures[change.id] = nil }
        // An interactive connection reports its own outcome.
        guard flows[change.id] == nil else { return }
        let name = displayName(change.id)
        // A security alert, whatever the notification settings.
        if change.state == .failed, let failure = change.failure, failure.code == .certificateChanged {
            Notifier.shared.post(title: String(localized: "\(name) disconnected"), body: label(failure))
            Windows.shared.showCertificateChanged(model: self, profile: change.id, failure: failure)
            return
        }
        switch change.state {
        case .connected where Settings.notifyConnected:
            Notifier.shared.post(title: String(localized: "\(name) connected"), body: change.detail ?? "")
        case .failed where Settings.notifyFailures && change.failure?.code != .cancelled:
            Notifier.shared.post(title: String(localized: "\(name) disconnected"), body: change.failure.map(label) ?? change.detail ?? "")
        default:
            break
        }
    }

    fileprivate func stopped(_ error: ClientError?) {
        subscription = nil
        sessions = [:]
        let wasRunning = if case .running = service { true } else { false }
        service = .unavailable(error.map(describe) ?? String(localized: "The service stopped."))
        if wasRunning, Settings.notifyFailures {
            Notifier.shared.post(
                title: String(localized: "\(brand.product) service stopped"),
                body: String(localized: "The VPNs are down. Trying again."))
        }
        watchRetry = Task {
            try? await Task.sleep(for: .seconds(5))
            if !Task.isCancelled { watch() }
        }
    }

    // MARK: Actions

    func toggle(_ id: String, on: Bool) {
        if on {
            connect(id)
        } else if let flow = flows[id] {
            flow.cancel()
        } else {
            disconnect(id)
        }
    }

    /// `direct`: without the VPNs the profile is chained through; `split`:
    /// only its split-mode networks go through the VPN.
    func connect(_ id: String, direct: Bool = false, split: Bool = false) {
        guard flows[id] == nil else { return }
        let others = exclusiveConflicts(id, direct: direct)
        guard others.isEmpty else {
            askToRunAlone(id, direct: direct, split: split, others: others)
            return
        }
        failures[id] = nil
        lastOptions[id] = (direct, split)
        let flow = ConnectionFlow(profile: id, direct: direct, split: split, model: self)
        flows[id] = flow
        flow.start(client: client)
    }

    /// Connects `id` again the way it was last connected (directly, in
    /// split mode).
    func connectAgain(_ id: String) {
        let options = lastOptions[id] ?? (false, false)
        connect(id, direct: options.direct, split: options.split)
    }

    /// What keeps `id` from connecting: a company VPN (exclusive) is never
    /// up at the same time as another VPN, those it goes through excepted.
    /// The same rule as the client library's, which refuses otherwise.
    private func exclusiveConflicts(_ id: String, direct: Bool) -> [String] {
        let via = direct ? [] : profile(id)?.via ?? []
        let alone = profile(id)?.exclusive ?? false
        let busy = Set(flows.keys).union(sessions.filter { [.connecting, .connected, .reconnecting].contains($0.value.state) }.keys)
        return busy.filter { $0 != id && !via.contains($0) && (alone || profile($0)?.exclusive == true) }
            .sorted { displayName($0) < displayName($1) }
    }

    /// The option decided on 25/10/2026: ask, with a button that
    /// disconnects the others then connects `id`.
    private func askToRunAlone(_ id: String, direct: Bool, split: Bool, others: [String]) {
        let name = displayName(id)
        let list = others.map(displayName).formatted(.list(type: .and))
        let alert = NSAlert()
        if profile(id)?.exclusive == true {
            alert.messageText = String(localized: "\(name) runs alone")
            alert.informativeText = String(localized: "\(name) is a company VPN: it is never connected at the same time as another VPN. Disconnect \(list) to connect it?")
        } else {
            alert.messageText = String(localized: "\(list) runs alone")
            alert.informativeText = String(localized: "\(list) is a company VPN: no other VPN is connected at the same time. Disconnect it to connect \(name)?")
        }
        alert.addButton(withTitle: String(localized: "Disconnect and Connect"))
        alert.addButton(withTitle: String(localized: "Cancel"))
        NSApp.activate()
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        for other in others { flows[other]?.cancel() }
        Task {
            await withTaskGroup(of: Void.self) { group in
                for other in others { group.addTask { [client] in try? await client.disconnect(id: other) } }
            }
            // The service's sessions follow by events: asking again now
            // could still see the others up.
            for other in others where sessions[other] != nil { sessions[other]?.state = .disconnected }
            connect(id, direct: direct, split: split)
        }
    }

    func disconnect(_ id: String) {
        failures[id] = nil
        Task {
            do {
                try await client.disconnect(id: id)
            } catch {
                failures[id] = describe(error)
            }
        }
    }

    func disconnectAll(timeout seconds: Double = 15) async {
        for flow in flows.values { flow.cancel() }
        let ids = Array(sessions.keys)
        let client = client
        await withTaskGroup(of: Void.self) { group in
            group.addTask {
                await withTaskGroup(of: Void.self) { each in
                    for id in ids { each.addTask { try? await client.disconnect(id: id) } }
                }
            }
            group.addTask { try? await Task.sleep(for: .seconds(seconds)) }
            await group.next()
            group.cancelAll()
        }
    }

    func restartService() {
        Task {
            do {
                try await client.shutdown()
            } catch {
                Windows.shared.alert(String(localized: "The service could not be restarted"), describe(error))
            }
        }
    }

    // MARK: Connection outcomes

    func flowChanged() {
        objectWillChange.send()
    }

    /// A chain brings up `profile` first: its row follows that part of the
    /// flow as if it had been started on its own.
    func flowReached(_ flow: ConnectionFlow, profile: String) {
        guard flows[flow.profile] === flow else { return }
        for (name, other) in flows where other === flow && name != flow.profile { flows[name] = nil }
        if profile != flow.profile, flows[profile] == nil { flows[profile] = flow }
    }

    func flowFinished(_ flow: ConnectionFlow, error: ClientError?) {
        guard flows[flow.profile] === flow else { return }
        for (name, other) in flows where other === flow { flows[name] = nil }
        // A chained VPN's failure may be the one it goes through: the
        // refused password, the forgotten secret are that one's.
        if let error { report(error, profile: flow.current) }
    }

    /// Explains a failure where it can be acted on; the rest shows in the
    /// menu and as a notification.
    private func report(_ error: ClientError, profile id: String) {
        guard case let .Failed(failure, message) = error else { return }
        let profile = displayName(id)
        switch failure.code {
        case .cancelled, .certificateUntrusted:
            // The user's own decision: nothing to report, and the daemon's
            // failed session is cleared so the menu does not show an error.
            Task { try? await client.disconnect(id: id) }
        case .certificateChanged:
            Windows.shared.showCertificateChanged(model: self, profile: id, failure: failure)
        case .authFailed:
            let forgotten = (try? client.deleteSecret(id: id, key: "password")) ?? false
            secretsDidChange()
            Windows.shared.alert(
                String(localized: "\(profile): user name or password refused"),
                forgotten ? String(localized: "The saved password was forgotten; it will be asked at the next connection.") : message)
        case .pskRejected:
            let forgotten = (try? client.deleteSecret(id: id, key: "psk")) ?? false
            secretsDidChange()
            Windows.shared.alert(
                String(localized: "\(profile): pre-shared key refused"),
                forgotten ? String(localized: "The saved key was forgotten; it will be asked at the next connection.") : message)
        case .conflict:
            explainConflict(profile: id, with: failure.conflictWith, message: message)
        case .otpRejected, .permissionDenied, .serviceUnavailable:
            Windows.shared.alert("\(profile): \(label(failure))", message)
            if failure.code == .serviceUnavailable { refreshService() }
        default:
            // The user asked for this connection: say why it failed, with
            // the way to the settings that may be at fault.
            failures[id] = label(failure)
            let alert = NSAlert()
            alert.messageText = String(localized: "\(profile): connection failed")
            alert.informativeText = message
            alert.addButton(withTitle: String(localized: "OK"))
            alert.addButton(withTitle: String(localized: "Edit \(profile)…"))
            NSApp.activate()
            if alert.runModal() == .alertSecondButtonReturn {
                Windows.shared.showManage(model: self, profile: id)
            }
        }
    }
}

extension AppModel {
    /// A VPN refused because of another one (mockup E9): the way out is to
    /// disconnect the other one, or change this one's networks.
    /// `profile` and `other`: profile ids.
    func explainConflict(profile id: String, with otherId: String?, message: String) {
        let (profile, other) = (displayName(id), otherId.map(displayName))
        let alert = NSAlert()
        alert.messageText = String(localized: "\(profile) was not connected")
        alert.informativeText = message
        alert.addButton(withTitle: String(localized: "Cancel"))
        if let other {
            alert.addButton(withTitle: String(localized: "Disconnect \(other) and Try Again"))
        }
        alert.addButton(withTitle: String(localized: "Edit \(profile)…"))
        NSApp.activate()
        let response = alert.runModal()
        switch (response, otherId) {
        case (.alertSecondButtonReturn, let otherId?):
            Task {
                try? await client.disconnect(id: otherId)
                connectAgain(id)
            }
        case (.alertSecondButtonReturn, nil), (.alertThirdButtonReturn, _):
            Windows.shared.showManage(model: self, profile: id)
        default:
            Task { try? await client.disconnect(id: id) }
        }
    }
}

/// Names a profile id for people (set by the model).
@MainActor var nameOf: (String) -> String = { $0 }

/// Short label of a failure, for the menu and titles.
@MainActor func label(_ failure: FailureInfo) -> String {
    switch failure.code {
    case .unreachable: String(localized: "server unreachable")
    case .authFailed: String(localized: "user name or password refused")
    case .otpRejected: String(localized: "code refused")
    case .pskRejected: String(localized: "pre-shared key refused")
    case .permissionDenied: String(localized: "access denied by the gateway")
    case .certificateUntrusted: String(localized: "certificate not trusted")
    case .certificateChanged: String(localized: "the server's certificate changed")
    case .conflict:
        failure.conflictWith.map { String(localized: "conflict with \(nameOf($0))") } ?? String(localized: "conflict with another VPN")
    case .needsUser: String(localized: "your input is needed")
    case .cancelled: String(localized: "cancelled")
    case .timeout: String(localized: "timed out")
    case .serviceUnavailable: String(localized: "service unavailable")
    case .other: String(localized: "error")
    }
}

/// Session events arrive on a Rust thread; they are handed to the main
/// queue in order.
private final class Observer: SessionObserver, @unchecked Sendable {
    private weak var model: AppModel?

    init(model: AppModel) { self.model = model }

    func sessions(sessions: [Session]) {
        DispatchQueue.main.async { MainActor.assumeIsolated { self.model?.received(sessions) } }
    }

    func changed(change: StateChange) {
        DispatchQueue.main.async { MainActor.assumeIsolated { self.model?.changed(change) } }
    }

    func stopped(error: ClientError?) {
        DispatchQueue.main.async { MainActor.assumeIsolated { self.model?.stopped(error) } }
    }
}
