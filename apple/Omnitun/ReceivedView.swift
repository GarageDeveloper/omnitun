// A .vpnprofile file opened from the Finder or Mail (mockup E12). The file
// is untrusted: its server and certificate fingerprints are shown before
// anything is added, and VPNClientCore refuses file paths and keys in it.

import SwiftUI
import VPNClientCore

struct ReceivedView: View {
    @ObservedObject var model: AppModel
    let fileName: String
    @State var received: ReceivedProfile
    let close: () -> Void
    @State private var error: String?

    private var form: ProfileForm { received.form }
    private var nameTaken: Bool { model.profiles.contains { $0.name == received.form.name } }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "doc.badge.plus").font(.system(size: 28)).foregroundStyle(.tint).frame(width: 36)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Add a VPN from a profile file").font(.headline)
                    Text(verbatim: fileName).font(.callout).foregroundStyle(.secondary)
                }
            }
            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 6) {
                GridRow {
                    Text("Type").foregroundStyle(.secondary)
                    Text(verbatim: kindName(form.kind))
                }
                GridRow {
                    Text("Server").foregroundStyle(.secondary)
                    Text(verbatim: "\(form.host):\(form.port)").bold().textSelection(.enabled)
                }
                let authorities = certificateNames(pem: form.caPem ?? "")
                if !authorities.isEmpty {
                    GridRow(alignment: .top) {
                        Text("Certificate Authority").foregroundStyle(.secondary)
                        VStack(alignment: .leading) {
                            ForEach(authorities, id: \.self) { Text(verbatim: $0).font(.caption).textSelection(.enabled) }
                        }
                    }
                }
                if !form.trustedCertificates.isEmpty {
                    GridRow(alignment: .top) {
                        Text("Certificate").foregroundStyle(.secondary)
                        VStack(alignment: .leading) {
                            ForEach(form.trustedCertificates, id: \.self) { fingerprint in
                                Text(verbatim: grouped(fingerprint))
                                    .font(.system(.caption, design: .monospaced))
                                    .textSelection(.enabled)
                            }
                        }
                    }
                }
                // What it changes in this Mac's routing and name resolution.
                if form.tunnelMode == .full {
                    GridRow {
                        Text("Traffic").foregroundStyle(.secondary)
                        Text("All traffic goes through this VPN").bold()
                    }
                }
                if let routes = form.routes, !routes.isEmpty {
                    GridRow(alignment: .top) {
                        Text("Networks").foregroundStyle(.secondary)
                        Text(verbatim: routes.joined(separator: ", ")).font(.caption).textSelection(.enabled)
                    }
                }
                if !form.dnsDomains.isEmpty {
                    GridRow(alignment: .top) {
                        Text("Name Resolution").foregroundStyle(.secondary)
                        VStack(alignment: .leading) {
                            ForEach(form.dnsDomains, id: \.self) { domain in
                                Text("Names ending in .\(domain)").font(.caption)
                                    .foregroundStyle(domain.contains(".") ? Color.primary : Color.orange)
                            }
                        }
                    }
                }
            }
            Text("Check the server and the fingerprint with whoever sent you this file before adding it.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Form {
                TextField("Name", text: $received.form.name)
                if nameTaken {
                    Text("A VPN of that name exists already: choose another name.").font(.caption).foregroundStyle(.orange)
                }
                if form.kind == .ipsec || form.kind == .l2tp || (form.kind == .fortiSsl && !form.saml) || (form.kind == .openVpn && form.passwordAuth) {
                    TextField("User Name", text: Binding(
                        get: { received.form.username ?? "" },
                        set: { received.form.username = $0.isEmpty ? nil : $0 }))
                }
            }
            .formStyle(.grouped)
            .frame(height: nameTaken ? 130 : 110)
            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                Button("Cancel", action: close).keyboardShortcut(.cancelAction)
                Button("Add") { add(connect: false) }.disabled(nameTaken)
                Button("Add and Connect") { add(connect: true) }.keyboardShortcut(.defaultAction).disabled(nameTaken)
            }
        }
        .padding(20)
        .frame(width: 500)
    }

    private func add(connect: Bool) {
        do {
            let id = try model.client.saveProfile(original: nil, form: received.form)
            model.reloadProfiles()
            model.imported = [id]
            close()
            if connect { model.connect(id) }
        } catch {
            self.error = describe(error)
        }
    }
}
