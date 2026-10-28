// Menu bar icon and menu (mockups E1, E2): one switch per VPN, like the
// Wi-Fi menu.

import AppKit
import Combine
import VPNClientCore

@MainActor
final class StatusMenu: NSObject, NSMenuDelegate {
    private let model: AppModel
    private let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    private let menu = NSMenu()
    private var rows: [String: VPNRow] = [:]
    private var header: NSMenuItem?
    private var isOpen = false
    private var changes: AnyCancellable?
    private var blink: Timer?
    private var blinkOn = false
    private var poll: Timer?

    init(model: AppModel) {
        self.model = model
        super.init()
        menu.delegate = self
        menu.autoenablesItems = false
        item.menu = menu
        item.button?.imagePosition = .imageLeading
        // The main queue, not RunLoop.main: an open menu runs the run loop in
        // tracking mode, where RunLoop.main would hold updates until it closes.
        changes = model.objectWillChange
            .receive(on: DispatchQueue.main)
            .sink { [weak self] in self?.refresh() }
        refresh()
    }

    // MARK: Icon

    private func refresh() {
        updateIcon()
        guard isOpen else { return }
        for (id, row) in rows { row.update(from: model, id: id) }
        header?.attributedTitle = headerTitle()
    }

    private func updateIcon() {
        let count = model.connectedCount
        let image: NSImage
        if model.hasProblem {
            image = HubIcon.symbol(filled: count > 0, alert: true)
        } else if model.isBusy {
            image = HubIcon.symbol(filled: blinkOn)
        } else {
            image = HubIcon.symbol(filled: count > 0)
        }
        image.accessibilityDescription = brand.product
        item.button?.image = image
        // The count from one on: a single VPN left up is easy to forget.
        item.button?.title = count > 0 ? " \(count)" : ""
        item.button?.toolTip = "\(brand.product) · \(summary())"

        // Connecting or reconnecting: the center fills and empties.
        if model.isBusy && !model.hasProblem, blink == nil {
            let timer = Timer(timeInterval: 0.6, repeats: true) { [weak self] _ in
                MainActor.assumeIsolated {
                    self?.blinkOn.toggle()
                    self?.updateIcon()
                }
            }
            // Common modes: keeps blinking while the menu is open.
            RunLoop.main.add(timer, forMode: .common)
            blink = timer
        } else if !model.isBusy || model.hasProblem {
            blink?.invalidate()
            blink = nil
            blinkOn = false
        }
    }

    private func summary() -> String {
        if case .unavailable = model.service { return String(localized: "service unavailable") }
        switch model.connectedCount {
        case 0: return String(localized: "no VPN connected")
        case 1: return String(localized: "1 connected")
        case let n: return String(localized: "\(n) connected")
        }
    }

    private func headerTitle() -> NSAttributedString {
        let title = NSMutableAttributedString(
            string: brand.product, attributes: [.font: NSFont.boldSystemFont(ofSize: NSFont.systemFontSize)])
        title.append(NSAttributedString(
            string: "   \(summary())",
            attributes: [.font: NSFont.menuFont(ofSize: NSFont.smallSystemFontSize), .foregroundColor: NSColor.secondaryLabelColor]))
        return title
    }

    // MARK: Menu

    func menuNeedsUpdate(_ menu: NSMenu) {
        model.reloadProfiles()
        rebuild()
    }

    /// While the menu is open, counters and durations move every second.
    func menuWillOpen(_ menu: NSMenu) {
        isOpen = true
        model.pollSessions()
        let timer = Timer(timeInterval: 1, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self, !self.model.sessions.isEmpty else { return }
                self.model.pollSessions()
            }
        }
        RunLoop.main.add(timer, forMode: .common)
        poll = timer
    }

    func menuDidClose(_ menu: NSMenu) {
        isOpen = false
        poll?.invalidate()
        poll = nil
    }

    private func rebuild() {
        menu.removeAllItems()
        rows = [:]

        let header = NSMenuItem()
        header.attributedTitle = headerTitle()
        header.isEnabled = false
        menu.addItem(header)
        self.header = header

        if case let .unavailable(reason) = model.service {
            let item = action(String(localized: "VPN service unavailable…"), #selector(openWelcome))
            item.image = NSImage(systemSymbolName: "exclamationmark.triangle.fill", accessibilityDescription: nil)
            item.toolTip = reason
            menu.addItem(item)
        }
        if let error = model.profilesError {
            let item = NSMenuItem(title: String(localized: "Unreadable profiles: \(error)"), action: nil, keyEquivalent: "")
            item.isEnabled = false
            menu.addItem(item)
        }

        menu.addItem(.separator())
        let ids = model.ids
        if ids.isEmpty {
            let empty = NSMenuItem(title: String(localized: "No VPN configured"), action: nil, keyEquivalent: "")
            empty.isEnabled = false
            menu.addItem(empty)
            menu.addItem(action(String(localized: "Add Your VPNs…"), #selector(openSetup)))
        }
        fill(menu, folder: nil, ids: ids)

        menu.addItem(.separator())
        let all = action(String(localized: "Disconnect All"), #selector(disconnectAll), key: "d")
        all.keyEquivalentModifierMask = [.command, .option]
        all.isEnabled = !model.sessions.isEmpty || !model.flows.isEmpty
        menu.addItem(all)

        menu.addItem(.separator())
        menu.addItem(action(String(localized: "Manage VPNs…"), #selector(openProfiles), key: ","))
        menu.addItem(action(String(localized: "Settings…"), #selector(openSettings)))
        if Updates.shared.available {
            menu.addItem(action(String(localized: "Check for Updates…"), #selector(checkForUpdates)))
        }
        menu.addItem(.separator())
        menu.addItem(action(String(localized: "Quit \(brand.product)"), #selector(quit), key: "q"))
    }

    /// The subfolders of `folder` as submenus, then its VPNs; VPNs without
    /// a profile (a session whose profile was removed) go at the top level.
    private func fill(_ target: NSMenu, folder: String?, ids: [String]) {
        let folderOf = { (id: String) in self.model.profile(id)?.folder }
        let prefix = folder.map { $0 + "/" } ?? ""
        let subfolders = Set(ids.compactMap(folderOf).filter { $0.hasPrefix(prefix) }
            .compactMap { $0.dropFirst(prefix.count).split(separator: "/").first.map(String.init) })
        for sub in subfolders.sorted(by: { $0.localizedStandardCompare($1) == .orderedAscending }) {
            let path = prefix + sub
            let inside = ids.filter { folderOf($0).map { $0 == path || $0.hasPrefix(path + "/") } ?? false }
            let up = inside.filter { model.sessions[$0]?.state == .connected }.count
            let item = NSMenuItem(title: up == 0 ? sub : String(localized: "\(sub) · \(up) connected"),
                                  action: nil, keyEquivalent: "")
            item.image = NSImage(systemSymbolName: up == 0 ? "folder" : "folder.fill", accessibilityDescription: nil)
            let submenu = NSMenu()
            submenu.autoenablesItems = false
            fill(submenu, folder: path, ids: ids)
            item.submenu = submenu
            target.addItem(item)
        }
        for id in ids where folderOf(id) == folder {
            addRow(id, to: target)
        }
    }

    private func addRow(_ id: String, to target: NSMenu) {
        let available: Bool = if case .unavailable = model.service { false } else { true }
        let row = VPNRow { [weak self] on in self?.model.toggle(id, on: on) }
        row.update(from: model, id: id)
        row.setEnabled(available)
        let item = NSMenuItem()
        item.view = row
        target.addItem(item)
        rows[id] = row
        // A chained VPN can also be brought up on its own; always listed,
        // so the menu does not change shape as it connects.
        if let profile = model.profile(id), !profile.via.isEmpty {
            let through = profile.via.map(model.displayName).joined(separator: " / ")
            let direct = action(String(localized: "Connect Directly, Without \(through)"),
                                #selector(connectDirectly(_:)))
            direct.representedObject = id
            direct.indentationLevel = 2
            direct.isEnabled = available && !model.isOn(id)
            target.addItem(direct)
        }
        // Always listed too, for the same reason.
        if let profile = model.profile(id), !profile.splitRoutes.isEmpty {
            let split = action(String(localized: "Connect in Split Mode"), #selector(connectSplit(_:)))
            split.toolTip = profile.splitRoutes.joined(separator: ", ")
            split.representedObject = id
            split.indentationLevel = 2
            split.isEnabled = available && !model.isOn(id)
            target.addItem(split)
        }
    }

    private func action(_ title: String, _ selector: Selector, key: String = "") -> NSMenuItem {
        let item = NSMenuItem(title: title, action: selector, keyEquivalent: key)
        item.target = self
        return item
    }

    @objc private func connectDirectly(_ sender: NSMenuItem) {
        if let id = sender.representedObject as? String { model.connect(id, direct: true) }
    }

    @objc private func connectSplit(_ sender: NSMenuItem) {
        if let id = sender.representedObject as? String { model.connect(id, split: true) }
    }

    @objc private func disconnectAll() { Task { await model.disconnectAll() } }
    @objc private func openWelcome() { afterMenu { Windows.shared.showWelcome(model: $0) } }
    @objc private func openSetup() { afterMenu { Windows.shared.showSetup(model: $0) } }
    @objc private func openProfiles() { afterMenu { Windows.shared.showManage(model: $0) } }
    @objc private func checkForUpdates() { afterMenu { _ in Updates.shared.checkNow() } }
    @objc private func openSettings() { afterMenu { Windows.shared.showSettings(model: $0) } }

    /// Runs `open` once the menu has closed: a window shown while the menu
    /// still tracks the mouse may fail to activate the app.
    private func afterMenu(_ open: @escaping @MainActor (AppModel) -> Void) {
        let model = model
        RunLoop.main.perform(inModes: [.default]) {
            MainActor.assumeIsolated { open(model) }
        }
    }
    @objc private func quit() { NSApp.terminate(nil) }
}

/// A VPN in the menu: state dot, name, one line of detail, and a switch.
final class VPNRow: NSView {
    private let dot = NSImageView()
    private let title = NSTextField(labelWithString: "")
    private let detail = NSTextField(labelWithString: "")
    private let toggle = NSSwitch()
    private let onToggle: (Bool) -> Void

    init(onToggle: @escaping (Bool) -> Void) {
        self.onToggle = onToggle
        super.init(frame: NSRect(x: 0, y: 0, width: 320, height: 44))
        title.font = .menuFont(ofSize: NSFont.systemFontSize)
        detail.font = .menuFont(ofSize: NSFont.smallSystemFontSize)
        detail.textColor = .secondaryLabelColor
        detail.lineBreakMode = .byTruncatingTail
        toggle.controlSize = .small
        toggle.target = self
        toggle.action = #selector(switched)
        let text = NSStackView(views: [title, detail])
        text.orientation = .vertical
        text.alignment = .leading
        text.spacing = 1
        for view in [dot, text, toggle] as [NSView] {
            view.translatesAutoresizingMaskIntoConstraints = false
            addSubview(view)
        }
        text.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        NSLayoutConstraint.activate([
            dot.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 14),
            dot.centerYAnchor.constraint(equalTo: centerYAnchor),
            dot.widthAnchor.constraint(equalToConstant: 16),
            text.leadingAnchor.constraint(equalTo: dot.trailingAnchor, constant: 8),
            text.centerYAnchor.constraint(equalTo: centerYAnchor),
            text.trailingAnchor.constraint(lessThanOrEqualTo: toggle.leadingAnchor, constant: -10),
            toggle.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -14),
            toggle.centerYAnchor.constraint(equalTo: centerYAnchor),
        ])
    }

    required init?(coder: NSCoder) { fatalError("not used") }

    @objc private func switched() { onToggle(toggle.state == .on) }

    /// Clicking anywhere on the row flips the switch.
    override func mouseUp(with event: NSEvent) {
        guard toggle.isEnabled else { return }
        toggle.state = toggle.state == .on ? .off : .on
        switched()
    }

    func setEnabled(_ enabled: Bool) { toggle.isEnabled = enabled }

    @MainActor
    func update(from model: AppModel, id: String) {
        let (text, color) = Self.describe(model: model, id: id)
        let name = model.displayName(id)
        title.stringValue = name
        detail.stringValue = text
        toggle.state = model.isOn(id) ? .on : .off
        dot.image = NSImage(systemSymbolName: "circle.fill", accessibilityDescription: nil)?
            .withSymbolConfiguration(.init(pointSize: 8, weight: .regular))
        dot.contentTintColor = color
        setAccessibilityLabel("\(name), \(text)")
    }

    @MainActor
    private static func describe(model: AppModel, id: String) -> (String, NSColor) {
        if let flow = model.flows[id] { return (flow.status(for: id), .systemOrange) }
        if let session = model.sessions[id] {
            switch session.state {
            case .connected:
                var parts = [String]()
                if let via = session.via { parts.append(String(localized: "via \(model.displayName(via))")) }
                if model.isSplit(id) { parts.append(String(localized: "split mode")) }
                if let address = session.address { parts.append(address) }
                parts.append("↓ \(bytes(session.rxBytes)) ↑ \(bytes(session.txBytes))")
                if let since = session.connectedSince { parts.append(duration(since: since)) }
                return (parts.joined(separator: " · "), .systemGreen)
            case .connecting:
                return (String(localized: "Connecting…"), .systemOrange)
            case .reconnecting:
                let text = model.retries[id].map {
                    String(localized: "Reconnecting (attempt \($0.attempt)/\($0.max))…")
                } ?? String(localized: "Reconnecting…")
                return (text, .systemOrange)
            case .disconnecting:
                return (String(localized: "Disconnecting…"), .tertiaryLabelColor)
            case .failed:
                let reason = session.failure.map(label) ?? session.detail ?? String(localized: "error")
                return (String(localized: "Failed: \(reason)"), .systemRed)
            case .disconnected:
                break
            }
        }
        if let failure = model.failures[id] { return (String(localized: "Failed: \(failure)"), .systemRed) }
        guard let profile = model.profile(id) else { return ("", .tertiaryLabelColor) }
        let kind = kindName(profile.protocol)
        if !profile.via.isEmpty {
            let through = profile.via.map(model.displayName).joined(separator: " / ")
            return ("\(kind) · \(String(localized: "via \(through)"))", .tertiaryLabelColor)
        }
        return ("\(kind) · \(profile.host)", .tertiaryLabelColor)
    }
}

func bytes(_ count: UInt64) -> String {
    ByteCountFormatter.string(fromByteCount: Int64(clamping: count), countStyle: .binary)
}

func duration(since: UInt64) -> String {
    let seconds = max(0, Int(Date().timeIntervalSince1970) - Int(since))
    if seconds < 60 { return "\(seconds) s" }
    if seconds < 3600 { return "\(seconds / 60) min" }
    return "\(seconds / 3600) h \(String(format: "%02d", seconds % 3600 / 60))"
}
