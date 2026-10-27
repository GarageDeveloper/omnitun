import Foundation
import UserNotifications

/// User notifications; silently off when the app runs outside its bundle
/// (`swift run`), where the notification center is not available.
@MainActor
final class Notifier {
    static let shared = Notifier()
    private var center: UNUserNotificationCenter? {
        Bundle.main.bundleIdentifier == nil ? nil : UNUserNotificationCenter.current()
    }

    func setUp() {
        Task {
            if await status() == .notDetermined { await requestAuthorization() }
        }
    }

    func status() async -> UNAuthorizationStatus? {
        await center?.notificationSettings().authorizationStatus
    }

    func requestAuthorization() async {
        _ = try? await center?.requestAuthorization(options: [.alert, .sound])
    }

    func post(title: String, body: String) {
        guard let center else { return }
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        center.add(UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil))
    }
}
