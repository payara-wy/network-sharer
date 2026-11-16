import AppKit
import Foundation

let side = 1024
guard let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: side, pixelsHigh: side,
                                     bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
                                     isPlanar: false, colorSpaceName: .deviceRGB,
                                     bytesPerRow: 0, bitsPerPixel: 0),
      let graphics = NSGraphicsContext(bitmapImageRep: bitmap) else { fatalError("Cannot create icon canvas") }
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = graphics
let c = graphics.cgContext
c.setAllowsAntialiasing(true)
c.setShouldAntialias(true)

// A rounded macOS tile with a soft, dark edge and a bright blue center.
let tile = CGRect(x: 76, y: 76, width: 872, height: 872)
let shape = CGPath(roundedRect: tile, cornerWidth: 205, cornerHeight: 205, transform: nil)
c.saveGState()
c.setShadow(offset: CGSize(width: 0, height: -18), blur: 35, color: NSColor.black.withAlphaComponent(0.23).cgColor)
c.addPath(shape)
c.setFillColor(NSColor(calibratedRed: 0.04, green: 0.28, blue: 0.75, alpha: 1).cgColor)
c.fillPath()
c.restoreGState()

c.saveGState()
c.addPath(shape)
c.clip()
let colorSpace = CGColorSpaceCreateDeviceRGB()
let colors = [NSColor(calibratedRed: 0.03, green: 0.72, blue: 0.98, alpha: 1).cgColor,
              NSColor(calibratedRed: 0.03, green: 0.45, blue: 0.94, alpha: 1).cgColor,
              NSColor(calibratedRed: 0.04, green: 0.22, blue: 0.70, alpha: 1).cgColor] as CFArray
let gradient = CGGradient(colorsSpace: colorSpace, colors: colors, locations: [0, 0.53, 1])!
c.drawLinearGradient(gradient, start: CGPoint(x: 170, y: 915), end: CGPoint(x: 850, y: 95), options: [])
let glowColors = [NSColor.white.withAlphaComponent(0.24).cgColor, NSColor.white.withAlphaComponent(0).cgColor] as CFArray
let glow = CGGradient(colorsSpace: colorSpace, colors: glowColors, locations: [0, 1])!
c.drawRadialGradient(glow, startCenter: CGPoint(x: 310, y: 825), startRadius: 0,
                     endCenter: CGPoint(x: 310, y: 825), endRadius: 620, options: [.drawsAfterEndLocation])
c.restoreGState()

// Wi-Fi waves join a branching path to two devices: one connection, shared.
c.setLineCap(.round)
c.setLineJoin(.round)
c.saveGState()
c.setShadow(offset: CGSize(width: 0, height: -7), blur: 13, color: NSColor(calibratedWhite: 0, alpha: 0.17).cgColor)
c.setStrokeColor(NSColor.white.cgColor)
c.setLineWidth(49)
let origin = CGPoint(x: 512, y: 440)
for radius in [CGFloat(292), CGFloat(208), CGFloat(124)] {
    c.beginPath()
    c.addArc(center: origin, radius: radius, startAngle: .pi * 0.25, endAngle: .pi * 0.75, clockwise: false)
    c.strokePath()
}
c.setFillColor(NSColor.white.cgColor)
c.fillEllipse(in: CGRect(x: 480, y: 408, width: 64, height: 64))
c.setLineWidth(33)
c.setStrokeColor(NSColor(calibratedRed: 0.81, green: 0.96, blue: 1, alpha: 1).cgColor)
c.beginPath()
c.move(to: CGPoint(x: 512, y: 382))
c.addLine(to: CGPoint(x: 512, y: 293))
c.move(to: CGPoint(x: 305, y: 238))
c.addCurve(to: CGPoint(x: 512, y: 293), control1: CGPoint(x: 305, y: 293), control2: CGPoint(x: 380, y: 293))
c.addCurve(to: CGPoint(x: 719, y: 238), control1: CGPoint(x: 644, y: 293), control2: CGPoint(x: 719, y: 293))
c.strokePath()
c.setFillColor(NSColor.white.cgColor)
for x in [CGFloat(305), CGFloat(719)] {
    c.fillEllipse(in: CGRect(x: x - 37, y: 201, width: 74, height: 74))
}
c.restoreGState()

// A restrained inner border helps the tile hold its shape in light and dark docks.
c.addPath(shape)
c.setStrokeColor(NSColor.white.withAlphaComponent(0.18).cgColor)
c.setLineWidth(3)
c.strokePath()
NSGraphicsContext.restoreGraphicsState()

guard CommandLine.arguments.count == 2,
      let data = bitmap.representation(using: .png, properties: [:]) else { fatalError("Expected output PNG path") }
try data.write(to: URL(fileURLWithPath: CommandLine.arguments[1]), options: .atomic)
