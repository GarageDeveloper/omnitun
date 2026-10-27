// Connection prompts (mockups E3 to E5, E7, E8).

import AppKit
import LocalAuthentication
import SecurityInterface
import SwiftUI
import VPNClientCore

private struct Header: View {
    let symbol: String
    let title: String
    let subtitle: String

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: symbol)
                .font(.system(size: 28))
                .foregroundStyle(.tint)
                .frame(width: 36)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.headline)
                Text(subtitle).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
    }
}

/// E3: password or pre-shared key. A key is always remembered; a password
/// by default, once the server accepted it, unless the profile asks for it
/// at every connection.
struct SecretPromptView: View {
    let profile: String
    let prompt: Prompt
    let canRemember: Bool
    let reply: (Prompts.Answer?) -> Void
    @State private var value = ""
    @State private var remember = true

    private var isKey: Bool { prompt.key == "psk" }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Header(symbol: "lock.fill", title: String(localized: "Connecting to \(profile)"), subtitle: prompt.message)
            SecureField(isKey ? String(localized: "Pre-shared key") : String(localized: "Password"), text: $value)
                .textFieldStyle(.roundedBorder)
            if isKey {
                Text("The key is saved to the Keychain once accepted.")
                    .font(.caption).foregroundStyle(.secondary)
            } else if canRemember {
                Toggle("Remember in the Keychain", isOn: $remember)
            }
            HStack {
                Spacer()
                Button("Cancel") { reply(nil) }.keyboardShortcut(.cancelAction)
                Button("Connect") { reply(.init(value: value, remember: isKey || (canRemember && remember))) }
                    .keyboardShortcut(.defaultAction)
                    .disabled(value.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 380)
    }
}

/// A visible value (user name, other questions); never remembered.
struct TextPromptView: View {
    let profile: String
    let prompt: Prompt
    let reply: (Prompts.Answer?) -> Void
    @State private var value = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Header(symbol: "person.crop.circle", title: String(localized: "Connecting to \(profile)"), subtitle: prompt.message)
            TextField("", text: $value).textFieldStyle(.roundedBorder)
            HStack {
                Spacer()
                Button("Cancel") { reply(nil) }.keyboardShortcut(.cancelAction)
                Button("Continue") { reply(.init(value: value, remember: false)) }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 380)
    }
}

/// E4: one-time code, sent at the 6th digit; with FortiToken push, an
/// approval on the phone instead.
struct CodePromptView: View {
    let profile: String
    let prompt: Prompt
    let reply: (Prompts.Answer?) -> Void
    @State private var code = ""
    @State private var waitingSince: Date?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            if let since = waitingSince {
                Header(symbol: "iphone.radiowaves.left.and.right", title: String(localized: "Approve on your phone"),
                       subtitle: "FortiToken Mobile · \(profile)")
                TimelineView(.periodic(from: since, by: 1)) { context in
                    let elapsed = Int(context.date.timeIntervalSince(since))
                    Text(String(format: String(localized: "Waiting… %d:%02d"), elapsed / 60, elapsed % 60))
                        .monospacedDigit().foregroundStyle(.secondary)
                }
            } else {
                Header(symbol: "number.square", title: String(localized: "Verification code"), subtitle: "\(profile) · \(prompt.message)")
                TextField("123456", text: $code)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 22, weight: .medium, design: .monospaced))
                    .onChange(of: code) { _, new in
                        let digits = new.filter(\.isNumber)
                        if digits != new { code = digits }
                        if digits.count == 6 { reply(.init(value: digits, remember: false)) }
                    }
                Text("The code is never saved.").font(.caption).foregroundStyle(.secondary)
                HStack {
                    if prompt.push {
                        Button("Approve on my phone") {
                            waitingSince = Date()
                            reply(.init(value: "", remember: false))
                        }
                    }
                    Spacer()
                    Button("Cancel") { reply(nil) }.keyboardShortcut(.cancelAction)
                    Button("Submit") { reply(.init(value: code, remember: false)) }
                        .keyboardShortcut(.defaultAction)
                        .disabled(code.isEmpty)
                }
            }
        }
        .padding(20)
        .frame(width: 380)
    }
}

/// E5: the login goes on in the system browser; this window closes by
/// itself once the gateway answers.
struct BrowserView: View {
    let profile: String
    let url: URL
    let cancel: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Header(symbol: "safari", title: String(localized: "Sign in with your browser"),
                   subtitle: String(localized: "\(profile) · finish signing in on the page that just opened. This window closes by itself."))
            HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Text(url.host() ?? "").font(.caption).foregroundStyle(.secondary)
            }
            HStack {
                Button("Reopen the Page") { NSWorkspace.shared.open(url) }
                Spacer()
                Button("Cancel", action: cancel).keyboardShortcut(.cancelAction)
            }
        }
        .padding(20)
        .frame(width: 400)
    }
}

/// SHA-256 in groups of four, as IT departments read it out.
func grouped(_ fingerprint: String) -> String {
    let hex = fingerprint.uppercased().filter(\.isHexDigit)
    return stride(from: 0, to: hex.count, by: 4).map { start in
        let from = hex.index(hex.startIndex, offsetBy: start)
        return String(hex[from..<(hex.index(from, offsetBy: 4, limitedBy: hex.endIndex) ?? hex.endIndex)])
    }.joined(separator: " ")
}

private func copy(_ text: String) {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(text, forType: .string)
}

private func showCertificate(_ der: Data) {
    guard let certificate = SecCertificateCreateWithData(nil, der as CFData) else { return }
    SFCertificatePanel.shared().runModal(forCertificates: [certificate], showGroup: false)
}

/// E7: first contact with a certificate that cannot be verified. Cancel is
/// the default button: Return never accepts.
struct TrustView: View {
    let profile: String
    let certificate: Certificate
    let reply: (TrustDecision) -> Void
    @State private var remember = true

    private var reason: String { certificate.reason.map { " (\($0))" } ?? "" }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Header(symbol: "checkmark.shield", title: String(localized: "Check the server's identity"),
                   subtitle: String(localized: "\(brand.product) cannot verify the certificate of \(certificate.host)\(reason). This is common with a FortiGate that uses its factory certificate. Compare the fingerprint below with the one given by your IT department."))
            VStack(alignment: .leading, spacing: 4) {
                Text("SHA-256").font(.caption).foregroundStyle(.secondary)
                Text(grouped(certificate.sha256))
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                HStack {
                    Button("Copy") { copy(certificate.sha256) }
                    if !certificate.der.isEmpty {
                        Button("Show Certificate") { showCertificate(certificate.der) }
                    }
                }
                .buttonStyle(.link)
            }
            .padding(10)
            .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 6))
            Toggle("Remember this certificate for \(profile)", isOn: $remember)
            HStack {
                Spacer()
                Button("Trust and Connect") { reply(remember ? .always : .once) }
                Button("Cancel") { reply(.reject) }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 460)
    }
}

/// E8: a pinned certificate was replaced. The connection stays blocked;
/// there is no way around it from here.
struct CertificateChangedView: View {
    let profile: String
    let presented: Certificate
    let pinned: [String]
    let close: () -> Void
    /// The user says IT confirmed the new certificate.
    let confirmed: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Header(symbol: "exclamationmark.shield.fill", title: String(localized: "The server's certificate changed"),
                   subtitle: String(localized: "\(presented.host) no longer presents the certificate you approved for \(profile). This can be a normal renewal, or an attempt to intercept your connection. Do not go on without confirmation from your IT department."))
            Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 6) {
                ForEach(pinned, id: \.self) { pin in
                    GridRow {
                        Text("Approved").foregroundStyle(.secondary)
                        Text(grouped(pin)).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                    }
                }
                GridRow {
                    Text("Presented").foregroundStyle(.secondary)
                    Text(grouped(presented.sha256)).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                }
            }
            Text("Only replace the certificate once your IT department has confirmed the new fingerprint.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            HStack {
                Button("Copy the Fingerprints for Support") {
                    let lines = pinned.map { String(localized: "approved: \($0)") }
                        + [String(localized: "presented: \(presented.sha256)")]
                    copy(lines.joined(separator: "\n"))
                }
                Spacer()
                Button("I Have Confirmed the New Certificate…", action: confirmed)
                Button("Don't Connect", action: close).keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 520)
    }
}

/// Replaces a changed certificate (decision 7 of the plan): the user types
/// the start of the new fingerprint, then proves who they are.
struct ReplaceCertificateView: View {
    @ObservedObject var model: AppModel
    let profile: String
    let presented: Certificate
    let close: () -> Void
    @State private var typed = ""
    @State private var error: String?

    private var expected: String { String(presented.sha256.uppercased().filter(\.isHexDigit).prefix(8)) }
    private var matches: Bool { typed.uppercased().filter(\.isHexDigit) == expected }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Header(symbol: "checkmark.shield", title: String(localized: "Trust the new certificate"),
                   subtitle: String(localized: "Type the first 8 characters of the new fingerprint, as your IT department gave it to you."))
            Text(verbatim: grouped(presented.sha256))
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
            TextField("First 8 characters", text: $typed)
                .font(.system(.body, design: .monospaced))
                .textFieldStyle(.roundedBorder)
            if let error {
                Text(verbatim: error).font(.caption).foregroundStyle(.red)
            }
            HStack {
                Spacer()
                Button("Cancel", action: close).keyboardShortcut(.cancelAction)
                Button("Replace and Connect") { replace() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!matches)
            }
        }
        .padding(20)
        .frame(width: 480)
    }

    private func replace() {
        let context = LAContext()
        let reason = String(localized: "replace the trusted certificate of \(model.displayName(profile))")
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { ok, failure in
            DispatchQueue.main.async {
                MainActor.assumeIsolated {
                    guard ok else {
                        error = failure?.localizedDescription
                        return
                    }
                    do {
                        try model.client.replaceTrustedCertificate(id: profile, sha256: presented.sha256)
                        close()
                        model.connect(profile)
                    } catch {
                        self.error = describe(error)
                    }
                }
            }
        }
    }
}
