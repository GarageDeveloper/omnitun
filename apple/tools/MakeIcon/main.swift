// Renders the app icon (HubIcon.drawAppIcon) at every size of a macOS
// .iconset; apple/package.sh turns it into AppIcon.icns with iconutil.
//   swiftc -o make-icon apple/Omnitun/HubIcon.swift apple/tools/MakeIcon/main.swift
//   ./make-icon <out>.iconset

import AppKit

guard CommandLine.arguments.count == 2 else {
    FileHandle.standardError.write("usage: make-icon <out>.iconset\n".data(using: .utf8)!)
    exit(2)
}
let out = URL(fileURLWithPath: CommandLine.arguments[1])
try FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)

func render(pixels: Int) -> Data {
    let rep = NSBitmapImageRep(
        bitmapDataPlanes: nil, pixelsWide: pixels, pixelsHigh: pixels, bitsPerSample: 8, samplesPerPixel: 4,
        hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    let context = NSGraphicsContext(bitmapImageRep: rep)!
    NSGraphicsContext.current = context
    context.imageInterpolation = .high
    // y-down, 100 units across.
    let transform = NSAffineTransform()
    transform.translateX(by: 0, yBy: CGFloat(pixels))
    transform.scaleX(by: CGFloat(pixels) / 100, yBy: -CGFloat(pixels) / 100)
    transform.concat()
    HubIcon.drawAppIcon()
    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}

for points in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let name = scale == 1 ? "icon_\(points)x\(points).png" : "icon_\(points)x\(points)@2x.png"
        try render(pixels: points * scale).write(to: out.appendingPathComponent(name))
    }
}
