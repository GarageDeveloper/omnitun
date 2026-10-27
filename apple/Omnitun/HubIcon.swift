// The icon (option F1 of the mockups): a hub whose lines run into tunnel
// mouths facing it. Drawn here once, for the menu bar symbol and, through
// apple/tools/MakeIcon, the app icon. Coordinates are y-down, like the SVG
// it comes from.

import AppKit

enum HubIcon {
    private struct Tunnel {
        let x: CGFloat
        let y: CGFloat
        /// Degrees, clockwise: the tunnel's mouth faces the center.
        let rotation: CGFloat
    }

    /// An arch from one foot over its top to the other, turned around
    /// its center.
    private static func arch(_ t: Tunnel, radius r: CGFloat, leg: CGFloat) -> NSBezierPath {
        let angle = t.rotation * .pi / 180
        func point(_ dx: CGFloat, _ dy: CGFloat) -> NSPoint {
            NSPoint(x: t.x + dx * cos(angle) - dy * sin(angle), y: t.y + dx * sin(angle) + dy * cos(angle))
        }
        let path = NSBezierPath()
        path.move(to: point(-r, leg))
        path.line(to: point(-r, 0))
        for step in 1...24 {
            let a = CGFloat.pi + CGFloat(step) / 24 * .pi
            path.line(to: point(r * cos(a), r * sin(a)))
        }
        path.line(to: point(r, leg))
        return path
    }

    /// From the center's edge to the tunnel's mouth.
    private static func spoke(to t: Tunnel, center: CGFloat, from start: CGFloat, mouth: CGFloat) -> NSBezierPath {
        let (dx, dy) = (center - t.x, center - t.y)
        let length = (dx * dx + dy * dy).squareRoot()
        let (ux, uy) = (dx / length, dy / length)
        let path = NSBezierPath()
        path.move(to: NSPoint(x: center - ux * start, y: center - uy * start))
        path.line(to: NSPoint(x: t.x + ux * mouth, y: t.y + uy * mouth))
        return path
    }

    private static func circle(_ x: CGFloat, _ y: CGFloat, _ r: CGFloat) -> NSBezierPath {
        NSBezierPath(ovalIn: NSRect(x: x - r, y: y - r, width: 2 * r, height: 2 * r))
    }

    private static func round(_ path: NSBezierPath, width: CGFloat) -> NSBezierPath {
        path.lineWidth = width
        path.lineCapStyle = .round
        path.lineJoinStyle = .round
        return path
    }

    // MARK: Menu bar

    /// Template symbol for the menu bar. `filled`: a VPN is connected,
    /// otherwise the symbol is dimmed like a Wi-Fi that is off; `alert`: an
    /// exclamation mark in the free corner.
    static func symbol(filled: Bool, alert: Bool = false) -> NSImage {
        let image = NSImage(size: NSSize(width: 18, height: 18), flipped: true) { _ in
            let transform = NSAffineTransform()
            transform.scale(by: 18.0 / 24.0)
            transform.concat()
            // Template images keep their alpha: a VPN that is up must show.
            NSColor.black.withAlphaComponent(filled || alert ? 1 : 0.55).set()
            let tunnels = [Tunnel(x: 5.2, y: 5.2, rotation: -45), Tunnel(x: 18.8, y: 5.2, rotation: 45),
                           Tunnel(x: 18.8, y: 18.8, rotation: 135)]
            for t in tunnels {
                round(arch(t, radius: 2.6, leg: 1.8), width: 1.8).stroke()
                round(spoke(to: t, center: 12, from: 4, mouth: 1.8), width: 1.8).stroke()
            }
            let center = circle(12, 12, filled ? 3.4 : 3)
            if filled { center.fill() } else { round(center, width: 1.5).stroke() }
            if alert {
                let mark = NSBezierPath()
                mark.move(to: NSPoint(x: 5, y: 13.5))
                mark.line(to: NSPoint(x: 5, y: 18))
                round(mark, width: 2.2).stroke()
                circle(5, 21.4, 1.2).fill()
            }
            return true
        }
        image.isTemplate = true
        return image
    }

    // MARK: App icon

    static let ground = NSColor(srgbRed: 0x24 / 255.0, green: 0x40 / 255.0, blue: 0x8E / 255.0, alpha: 1)
    static let accent = NSColor(srgbRed: 0x7F / 255.0, green: 0xD1 / 255.0, blue: 0xFF / 255.0, alpha: 1)

    /// Draws the app icon in a 100 × 100 y-down space, on Apple's grid (the
    /// rounded square takes 824 of 1024 points).
    static func drawAppIcon() {
        let inset: CGFloat = 100 * 100 / 1024
        ground.setFill()
        NSBezierPath(roundedRect: NSRect(x: inset, y: inset, width: 100 - 2 * inset, height: 100 - 2 * inset),
                     xRadius: 18, yRadius: 18).fill()

        // The mockup's artwork sat on a slightly larger square.
        let fit = NSAffineTransform()
        fit.translateX(by: 50, yBy: 50)
        fit.scale(by: (100 - 2 * inset) / 88)
        fit.translateX(by: -50, yBy: -50)
        fit.concat()

        NSColor.white.withAlphaComponent(0.25).setStroke()
        round(circle(50, 50, 27), width: 3).stroke()
        let tunnels = [Tunnel(x: 31, y: 31, rotation: -45), Tunnel(x: 69, y: 31, rotation: 45),
                       Tunnel(x: 69, y: 69, rotation: 135), Tunnel(x: 31, y: 69, rotation: -135)]
        NSColor.white.setStroke()
        for t in tunnels { round(spoke(to: t, center: 50, from: 0, mouth: 4), width: 4).stroke() }
        for (i, t) in tunnels.enumerated() {
            (i == 2 ? accent : NSColor.white).setStroke()
            round(arch(t, radius: 7, leg: 4), width: 4.5).stroke()
        }
        NSColor.white.setFill()
        circle(50, 50, 10).fill()
    }
}
