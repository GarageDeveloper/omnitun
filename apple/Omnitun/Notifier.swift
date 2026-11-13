import Foundation
import UserNotifications

/// User notifications; silently off when the app runs outside its bundle
/// (`swift run`), where the notification center is not available.
@MainActor
final class Notifier: NSObject, UNUserNotificationCenterDelegate {
    static let shared = Notifier()
    private var center: UNUserNotificationCenter? {
        Bundle.main.bundleIdentifier == nil ? nil : UNUserNotificationCenter.current()
    }

    /// A disconnection to come, with a button to put it off.
    private nonisolated static let expiringCategory = "expiring"
    private nonisolated static let postponeAction = "postpone"

    /// Called with the profile id when the user asks to put off its
    /// automatic disconnection from a notification.
    var onPostpone: (String) -> Void = { _ in }

    func setUp() {
        if let center {
            center.delegate = self
            let postpone = UNNotificationAction(identifier: Self.postponeAction,
                                                title: String(localized: "Postpone"), options: [])
            center.setNotificationCategories([
                UNNotificationCategory(identifier: Self.expiringCategory, actions: [postpone], intentIdentifiers: []),
            ])
        }
        Task {
            if await status() == .notDetermined { await requestAuthorization() }
        }
    }

    func status() async -> UNAuthorizationStatus? {
        await center?.notificationSettings().authorizationStatus
    }

    /// One request at a time: a second one while the system prompt is up
    /// fails at once, before the user answers.
    private var pending: Task<Void, Never>?

    func requestAuthorization() async {
        if let pending { return await pending.value }
        let request = Task { _ = try? await center?.requestAuthorization(options: [.alert, .sound]) }
        pending = request
        await request.value
        pending = nil
    }

    func post(title: String, body: String) {
        guard let center else { return }
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        center.add(UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil))
    }

    /// `id`'s disconnection to come; one at a time per VPN, replaced by
    /// the next. `canPostpone`: with the Postpone button.
    func postExpiring(id: String, title: String, body: String, canPostpone: Bool) {
        guard let center else { return }
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default
        content.userInfo = ["id": id]
        if canPostpone { content.categoryIdentifier = Self.expiringCategory }
        center.add(UNNotificationRequest(identifier: Self.expiringIdentifier(id), content: content, trigger: nil))
    }

    /// Takes back `id`'s warning: postponed, or already disconnected.
    func removeExpiring(id: String) {
        center?.removeDeliveredNotifications(withIdentifiers: [Self.expiringIdentifier(id)])
    }

    private static func expiringIdentifier(_ id: String) -> String { "expiring-\(id)" }

    // MARK: UNUserNotificationCenterDelegate

    /// Shown as banners even though the menu bar app is always active.
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification)
        async -> UNNotificationPresentationOptions {
        [.banner, .list, .sound]
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter,
                                            didReceive response: UNNotificationResponse) async {
        guard response.actionIdentifier == Self.postponeAction,
              let id = response.notification.request.content.userInfo["id"] as? String else { return }
        await MainActor.run { onPostpone(id) }
    }
}
