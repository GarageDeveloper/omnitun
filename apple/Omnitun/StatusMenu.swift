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
    /// Folder submenus, with the VPNs they hold, to count them as they connect.
    private var folders: [(item: NSMenuItem, name: String, ids: [String])] = []
    /// The other ways to connect a VPN ("Connect Directly"…), and "Disconnect
    /// All": enabled by the sessions, which change while the menu is open.
    private var alternatives: [(item: NSMenuItem, id: String)] = []
    private var disconnectAllItem: NSMenuItem?
    private var unavailableItem: NSMenuItem?
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
        for (id, row) in rows {
            row.update(from: model, id: id)
            row.setEnabled(serviceAvailable)
        }
        for (item, id) in alternatives { item.isEnabled = serviceAvailable && !model.isOn(id) }
        disconnectAllItem?.isEnabled = canDisconnectAll
        showServiceState()
        for folder in folders { label(folder.item, name: folder.name, ids: folder.ids) }
        header?.attributedTitle = headerTitle()
    }

    /// "VPN service unavailable…" shown, with the reason, only while it is.
    private func showServiceState() {
        guard let item = unavailableItem else { return }
        if case let .unavailable(reason) = model.service {
            item.isHidden = false
            item.toolTip = reason
        } else {
            item.isHidden = true
        }
    }

    private var serviceAvailable: Bool {
        if case .unavailable = model.service { false } else { true }
    }

    private var canDisconnectAll: Bool { !model.sessions.isEmpty || !model.flows.isEmpty }

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
        folders = []
        alternatives = []

        let header = NSMenuItem()
        header.attributedTitle = headerTitle()
        header.isEnabled = false
        menu.addItem(header)
        self.header = header

        // Always there, hidden while the service runs: it can stop while the
        // menu is open.
        let unavailable = action(String(localized: "VPN service unavailable…"), #selector(openWelcome),
                                 symbol: "exclamationmark.triangle.fill")
        menu.addItem(unavailable)
        unavailableItem = unavailable
        showServiceState()
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
            menu.addItem(action(String(localized: "Add Your VPNs…"), #selector(openSetup), symbol: "plus"))
        }
        fill(menu, folder: nil, ids: ids)

        menu.addItem(.separator())
        let all = action(String(localized: "Disconnect All"), #selector(disconnectAll), key: "d", symbol: "xmark.circle")
        all.keyEquivalentModifierMask = [.command, .option]
        all.isEnabled = canDisconnectAll
        menu.addItem(all)
        disconnectAllItem = all

        menu.addItem(.separator())
        menu.addItem(action(String(localized: "Manage VPNs…"), #selector(openProfiles), key: ",", symbol: "list.bullet"))
        menu.addItem(action(String(localized: "Settings…"), #selector(openSettings), symbol: "gearshape"))
        menu.addItem(action(String(localized: "About \(brand.product)"), #selector(openAbout), symbol: "info.circle"))
        if Updates.shared.available {
            menu.addItem(action(String(localized: "Check for Updates…"), #selector(checkForUpdates),
                                symbol: "arrow.triangle.2.circlepath"))
        }
        menu.addItem(.separator())
        menu.addItem(action(String(localized: "Quit \(brand.product)"), #selector(quit), key: "q", symbol: "power"))
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
            let item = NSMenuItem(title: sub, action: nil, keyEquivalent: "")
            label(item, name: sub, ids: inside)
            folders.append((item, sub, inside))
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

    /// A folder's title and icon: how many of its VPNs are connected.
    private func label(_ item: NSMenuItem, name: String, ids: [String]) {
        let up = ids.filter { model.sessions[$0]?.state == .connected }.count
        item.title = up == 0 ? name : String(localized: "\(name) · \(up) connected")
        item.image = NSImage(systemSymbolName: up == 0 ? "folder" : "folder.fill", accessibilityDescription: nil)
    }

    private func addRow(_ id: String, to target: NSMenu) {
        let row = VPNRow { [weak self] on in self?.model.toggle(id, on: on) }
        row.update(from: model, id: id)
        row.setEnabled(serviceAvailable)
        let item = NSMenuItem()
        item.view = row
        target.addItem(item)
        rows[id] = row
        // A chained VPN can also be brought up on its own; always listed,
        // so the menu does not change shape as it connects.
        if let profile = model.profile(id), !profile.via.isEmpty {
            let through = profile.via.map(model.displayName).joined(separator: " / ")
            let direct = action(String(localized: "Connect Directly, Without \(through)"),
                                #selector(connectDirectly(_:)), symbol: "arrow.turn.down.right")
            direct.representedObject = id
            direct.indentationLevel = 2
            direct.isEnabled = serviceAvailable && !model.isOn(id)
            target.addItem(direct)
            alternatives.append((direct, id))
        }
        // Always listed too, for the same reason.
        if let profile = model.profile(id), !profile.splitRoutes.isEmpty {
            let split = action(String(localized: "Connect in Split Mode"), #selector(connectSplit(_:)),
                               symbol: "arrow.triangle.branch")
            split.toolTip = profile.splitRoutes.joined(separator: ", ")
            split.representedObject = id
            split.indentationLevel = 2
            split.isEnabled = serviceAvailable && !model.isOn(id)
            target.addItem(split)
            alternatives.append((split, id))
        }
    }

    /// `symbol`: every action has an icon, so that the menu reads as one
    /// column (macOS gives some standard entries an icon of its own).
    private func action(_ title: String, _ selector: Selector, key: String = "", symbol: String) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: selector, keyEquivalent: key)
        item.target = self
        item.image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)
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
    @objc private func openAbout() { afterMenu { Windows.shared.showSettings(model: $0, tab: .about) } }

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
    private let toggle = MenuSwitch()
    private let onToggle: (Bool) -> Void

    init(onToggle: @escaping (Bool) -> Void) {
        self.onToggle = onToggle
        super.init(frame: NSRect(x: 0, y: 0, width: 320, height: 44))
        title.font = .menuFont(ofSize: NSFont.systemFontSize)
        detail.font = .menuFont(ofSize: NSFont.smallSystemFontSize)
        detail.textColor = .secondaryLabelColor
        detail.lineBreakMode = .byTruncatingTail
        toggle.onPress = { [weak self] in self?.flip() }
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

    private func flip() {
        guard toggle.isEnabled else { return }
        toggle.isOn.toggle()
        onToggle(toggle.isOn)
    }

    /// Clicking anywhere on the row, the switch included, flips the switch;
    /// so does releasing on it after a drag from the menu bar icon, as for
    /// any menu entry.
    override func mouseUp(with event: NSEvent) { flip() }

    /// Clicks go to the row, but VoiceOver's pointer finds the switch.
    override func accessibilityHitTest(_ point: NSPoint) -> Any? {
        guard let window else { return super.accessibilityHitTest(point) }
        let local = convert(window.convertPoint(fromScreen: point), from: nil)
        return toggle.frame.contains(local) ? toggle : super.accessibilityHitTest(point)
    }

    func setEnabled(_ enabled: Bool) { toggle.isEnabled = enabled }

    @MainActor
    func update(from model: AppModel, id: String) {
        let (text, color) = Self.describe(model: model, id: id)
        let name = model.displayName(id)
        title.stringValue = name
        detail.stringValue = text
        toggle.isOn = model.isOn(id)
        toggle.setAccessibilityLabel(name)
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

/// The switch of a VPN row. An NSSwitch in the menu of an app that is not
/// frontmost (always the case for a menu bar app) is drawn grey when on,
/// in a shade that depends on how its state was last set, and blue only
/// right after a click: this one draws itself, in the accent colour when on.
/// It takes no clicks: the row flips it.
final class MenuSwitch: NSView {
    var isOn = false {
        didSet {
            guard isOn != oldValue else { return }
            needsDisplay = true
            NSAccessibility.post(element: self, notification: .valueChanged)
        }
    }
    var isEnabled = true {
        didSet { alphaValue = isEnabled ? 1 : 0.5 }
    }
    /// VoiceOver's press.
    var onPress: (() -> Void)?

    override var intrinsicContentSize: NSSize { NSSize(width: 28, height: 16) }

    override func hitTest(_ point: NSPoint) -> NSView? { nil }

    override func draw(_ dirtyRect: NSRect) {
        let track = NSBezierPath(roundedRect: bounds, xRadius: bounds.height / 2, yRadius: bounds.height / 2)
        (isOn ? NSColor.controlAccentColor : NSColor.quaternaryLabelColor).setFill()
        track.fill()
        let inset: CGFloat = 1.5
        let side = bounds.height - 2 * inset
        let x = isOn ? bounds.maxX - inset - side : bounds.minX + inset
        let knob = NSBezierPath(ovalIn: NSRect(x: x, y: bounds.minY + inset, width: side, height: side))
        NSGraphicsContext.saveGraphicsState()
        let shadow = NSShadow()
        shadow.shadowColor = .black.withAlphaComponent(0.3)
        shadow.shadowBlurRadius = 1
        shadow.shadowOffset = NSSize(width: 0, height: -0.5)
        shadow.set()
        NSColor.white.setFill()
        knob.fill()
        NSGraphicsContext.restoreGraphicsState()
    }

    override func isAccessibilityElement() -> Bool { true }
    override func accessibilityRole() -> NSAccessibility.Role? { .checkBox }
    override func accessibilitySubrole() -> NSAccessibility.Subrole? { .switch }
    override func accessibilityValue() -> Any? { NSNumber(value: isOn) }
    override func isAccessibilityEnabled() -> Bool { isEnabled }
    override func accessibilityPerformPress() -> Bool {
        guard isEnabled, let onPress else { return false }
        onPress()
        return true
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
