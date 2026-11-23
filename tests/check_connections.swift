import SwiftUI
import AppKit

// The report renders without starting a relay or collecting real process data.
final class ProxyClient: ObservableObject {
    let activitySocket: String? = nil
    let ready = false
}

@main enum ConnectionsLayoutCheck {
    @MainActor static func main() {
        _ = NSApplication.shared
        let longDomain = String(repeating: "long-segment.", count: 8) + "example.test"
        let rows = (1...60).map { index in
            ConnectionRow(App: String(format: "Приложение %02d", index),
                          Domain: longDomain, Route: index.isMultiple(of: 3) ? "outside" : "guard",
                          Count: 12)
        }
        func scrollView(in view: NSView) -> NSScrollView? {
            if let scroll = view as? NSScrollView { return scroll }
            return view.subviews.compactMap { scrollView(in: $0) }.first
        }
        for height: CGFloat in [135, 420] {
            let report = ConnectionSnapshot(Rows: rows, Registry: true, DNS: true)
            let view = NSHostingView(rootView: ConnectionReport(report: report, height: height)
                .frame(width: 360).fixedSize(horizontal: false, vertical: true))
            let window = NSWindow(contentRect: NSRect(origin: .zero, size: view.fittingSize),
                                  styleMask: [.borderless], backing: .buffered, defer: false)
            window.contentView = view
            view.layoutSubtreeIfNeeded()
            guard let scroll = scrollView(in: view), let document = scroll.documentView else {
                fatalError("Missing native scroll view")
            }
            let clip = scroll.contentView
            precondition(abs(clip.bounds.height - height) <= 2)
            precondition(document.bounds.height > 60 * 50 && document.bounds.width <= 360)
            let bottom = max(0, document.frame.height - clip.bounds.height)
            clip.scroll(to: CGPoint(x: 0, y: bottom))
            scroll.reflectScrolledClipView(clip)
            precondition(abs(scroll.documentVisibleRect.maxY - document.bounds.maxY) <= 2)
            print("60 apps: viewport", Int(height), "bottom", Int(scroll.documentVisibleRect.maxY),
                  "of", Int(document.bounds.maxY))
        }
    }
}
