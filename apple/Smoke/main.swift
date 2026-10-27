// Checks that the generated bindings link and behave, without the app:
//   apple/build-bindings.sh && swift run --package-path apple Smoke
import Foundation
import VPNClientCore

let dir = FileManager.default.temporaryDirectory.appendingPathComponent("vpn-smoke-\(getpid())")
try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
defer { try? FileManager.default.removeItem(at: dir) }

let client = try Client(configPath: dir.appendingPathComponent("profiles.toml").path)
let initial = try client.profiles()
precondition(initial.isEmpty)

let added = try client.addProfiles(toml: """
    [[profile]]
    name = "paris"
    protocol = "forti-ssl"
    host = "vpn.example.com"
    port = 4443
    """)
precondition(added == ["paris"])
let listed = try client.profiles()
let paris = listed[0]
precondition(paris.host == "vpn.example.com" && paris.port == 4443 && paris.auth == .password)
print("profiles ok: \(paris.name) \(paris.protocol) \(paris.host):\(paris.port)")

do {
    _ = try client.addProfiles(toml: "[[profile]]\nname = \"bad\"\nprotocol = \"forti-ssl\"\nhost = \"not a host\"\n")
    fatalError("an invalid host was accepted")
} catch ClientError.Failed(let failure, let message) {
    print("invalid profile refused: \(failure.code) \(message)")
}

if let imported = try? client.importForticlient(path: nil) {
    print("forticlient: \(imported.map(\.name))")
}

// A running daemon, read-only: SMOKE_SOCKET=/tmp/omnitund.sock
if let socket = ProcessInfo.processInfo.environment["SMOKE_SOCKET"] {
    setenv("OMNITUN_SOCKET", socket, 1)
    for s in try await client.sessions() {
        print("session \(s.name): \(s.state) \(s.interface ?? "-") rx \(s.rxBytes) tx \(s.txBytes)")
    }
}

// With no daemon on this socket, errors arrive typed.
setenv("OMNITUN_SOCKET", dir.appendingPathComponent("none.sock").path, 1)
do {
    _ = try await client.sessions()
    fatalError("sessions without a daemon")
} catch ClientError.Failed(let failure, let message) {
    precondition(failure.code == .serviceUnavailable, "\(failure.code)")
    print("no daemon: \(message)")
}

final class Delegate: ConnectionDelegate, @unchecked Sendable {
    let done = DispatchSemaphore(value: 0)
    var error: ClientError?
    func prompt(id: UInt64, prompt: Prompt) {}
    func trustCertificate(id: UInt64, certificate: Certificate) {}
    func openUrl(url: String) {}
    func notice(notice: Notice) { print("notice: \(notice)") }
    func finished(error: ClientError?) { self.error = error; done.signal() }
}
let delegate = Delegate()
let connection = client.connect(id: "paris", direct: false, delegate: delegate)
precondition(delegate.done.wait(timeout: .now() + 5) == .success, "finished was not called")
guard case .Failed(let failure, _) = delegate.error, failure.code == .serviceUnavailable else {
    fatalError("connect without daemon: \(String(describing: delegate.error))")
}
_ = connection
print("smoke ok")
