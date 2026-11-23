import Foundation
import SystemConfiguration

// launchd supplies the client requirement from its root-owned plist.
final class RuleService: NSObject, NSXPCListenerDelegate, GuardRuleControl {
    private let writes = DispatchQueue(label: "local.aiexitguard.rules.write")

    private func isConsoleUser(_ connection: NSXPCConnection?) -> Bool {
        var uid: uid_t = 0
        guard let connection, SCDynamicStoreCopyConsoleUser(nil, &uid, nil) != nil,
              uid != 0 else { return false }
        return connection.effectiveUserIdentifier == uid
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection peer: NSXPCConnection) -> Bool {
        guard isConsoleUser(peer) else { return false }
        peer.exportedInterface = NSXPCInterface(with: GuardRuleControl.self)
        peer.exportedObject = self
        peer.resume()
        return true
    }

    func ping(withReply reply: @escaping (Bool) -> Void) {
        reply(isConsoleUser(NSXPCConnection.current()))
    }

    func setProtection(_ enabled: Bool, withReply reply: @escaping (Bool) -> Void) {
        let peer = NSXPCConnection.current()
        writes.async {
            guard self.isConsoleUser(peer) else { reply(false); return }
            let args = ["-e", DirectRouteLock.editor, "--", "/private/etc",
                        enabled ? "on" : "off", DirectRouteLock.block]
            let applied = self.run("/usr/bin/perl", args)
                && self.run("/usr/bin/dscacheutil", ["-flushcache"])
                && self.run("/usr/bin/killall", ["-HUP", "mDNSResponder"])
            reply(applied && DirectRouteLock.read() == (enabled ? .on : .off))
        }
    }

    private func run(_ executable: String, _ arguments: [String]) -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        process.currentDirectoryURL = URL(fileURLWithPath: "/")
        process.arguments = arguments
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            process.waitUntilExit()
            return process.terminationStatus == 0
        } catch { return false }
    }
}

guard geteuid() == 0, CommandLine.arguments.count == 2 else { exit(1) }
let listener = NSXPCListener(machServiceName: guardServiceName)
listener.setConnectionCodeSigningRequirement(CommandLine.arguments[1])
let service = RuleService()
listener.delegate = service
listener.resume()
RunLoop.main.run()
