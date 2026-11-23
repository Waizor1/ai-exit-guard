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
        NSGradient(starting:NSColor(srgbRed:0.10,green:0.39,blue:0.37,alpha:1),
                   ending:NSColor(srgbRed:0.05,green:0.15,blue:0.24,alpha:1))!.draw(in:tile,angle:65)
        let shield = NSBezierPath()
        shield.move(to:NSPoint(x:64,y:99));shield.line(to:NSPoint(x:95,y:88))
        shield.line(to:NSPoint(x:94,y:63))
        shield.curve(to:NSPoint(x:64,y:29),controlPoint1:NSPoint(x:94,y:48),controlPoint2:NSPoint(x:77,y:35))
        shield.curve(to:NSPoint(x:34,y:63),controlPoint1:NSPoint(x:51,y:35),controlPoint2:NSPoint(x:34,y:48))
        shield.line(to:NSPoint(x:33,y:88));shield.close()
        NSColor(srgbRed:0.75,green:0.96,blue:0.86,alpha:1).setFill();shield.fill()
        let check = NSBezierPath()
        check.move(to:NSPoint(x:49,y:65));check.line(to:NSPoint(x:60,y:54));check.line(to:NSPoint(x:80,y:76))
        check.lineCapStyle = .round;check.lineJoinStyle = .round;check.lineWidth=7
        NSColor(srgbRed:0.07,green:0.30,blue:0.30,alpha:1).setStroke();check.stroke()
        NSGraphicsContext.restoreGraphicsState()
        let suffix = scale==2 ? "@2x" : ""
        let name = "icon_\(size)x\(size)\(suffix).png"
        try bitmap.representation(using:.png,properties:[:])!.write(to:folder.appendingPathComponent(name))
    }
}
