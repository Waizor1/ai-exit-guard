import AppKit

// Render the Finder icon at each native size so small variants have crisp edges.
let folder = URL(fileURLWithPath:CommandLine.arguments[1])
for size in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let pixels = size * scale
        let bitmap = NSBitmapImageRep(bitmapDataPlanes:nil, pixelsWide:pixels, pixelsHigh:pixels,
            bitsPerSample:8, samplesPerPixel:4, hasAlpha:true, isPlanar:false, colorSpaceName:.deviceRGB,
            bytesPerRow:0, bitsPerPixel:0)!
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep:bitmap)
        let transform = NSAffineTransform()
        transform.scale(by:CGFloat(pixels)/128)
        transform.concat()
        let tile = NSBezierPath(roundedRect:NSRect(x:8,y:8,width:112,height:112), xRadius:26,yRadius:26)
        NSGradient(starting:NSColor(srgbRed:0.11,green:0.13,blue:0.18,alpha:1),
                   ending:NSColor(srgbRed:0.05,green:0.06,blue:0.09,alpha:1))!.draw(in:tile,angle:-90)
        NSColor(white:1.0,alpha:0.12).setStroke()
        tile.lineWidth = 2.0
        tile.stroke()

        // Soft emerald ambient glow behind core
        if let glow = NSGradient(colorsAndLocations:
            (NSColor(srgbRed:0.20,green:0.83,blue:0.60,alpha:0.26), 0.0),
            (NSColor(srgbRed:0.20,green:0.83,blue:0.60,alpha:0.0), 1.0)) {
            glow.draw(fromCenter:NSPoint(x:64,y:65), radius:2, toCenter:NSPoint(x:64,y:65), radius:34, options:[])
        }

        // Crisp luminous shield contour matching menu bar glyph
        let shield = NSBezierPath()
        shield.move(to:NSPoint(x:64,y:98))
        shield.line(to:NSPoint(x:93,y:87))
        shield.curve(to:NSPoint(x:95,y:83), controlPoint1:NSPoint(x:94.5,y:86.2), controlPoint2:NSPoint(x:95,y:84.8))
        shield.line(to:NSPoint(x:95,y:64))
        shield.curve(to:NSPoint(x:64,y:27), controlPoint1:NSPoint(x:95,y:46), controlPoint2:NSPoint(x:82,y:33))
        shield.curve(to:NSPoint(x:33,y:64), controlPoint1:NSPoint(x:46,y:33), controlPoint2:NSPoint(x:33,y:46))
        shield.line(to:NSPoint(x:33,y:83))
        shield.curve(to:NSPoint(x:35,y:87), controlPoint1:NSPoint(x:33,y:84.8), controlPoint2:NSPoint(x:33.5,y:86.2))
        shield.close()
        shield.lineWidth = 8.2
        shield.lineJoinStyle = .round
        shield.lineCapStyle = .round
        NSColor(srgbRed:0.93,green:0.95,blue:0.98,alpha:1).setStroke()
        shield.stroke()

        // Glowing emerald core dot
        let core = NSBezierPath(ovalIn:NSRect(x:52.5,y:53.5,width:23,height:23))
        NSColor(srgbRed:0.22,green:0.85,blue:0.62,alpha:1).setFill()
        core.fill()
        NSGraphicsContext.restoreGraphicsState()
        let suffix = scale==2 ? "@2x" : ""
        let name = "icon_\(size)x\(size)\(suffix).png"
        try bitmap.representation(using:.png,properties:[:])!.write(to:folder.appendingPathComponent(name))
    }
}
