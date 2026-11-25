import Foundation
import SystemConfiguration

// Keep root's policy independent of any per-user discovery or configuration.
enum DNSLeasePolicy {
    static let hosts: Set<String> = embeddedMCPHosts

    static func permits(_ names: [String]) -> Bool {
        guard (1...10).contains(names.count) else { return false }
        let requested = Set(names)
        return requested.count == names.count && requested.isSubset(of: hosts) &&
            !names.contains { name in
                protectedDomains.contains { overlaps(name, $0) }
            }
    }

    static func overlaps(_ left: String, _ right: String) -> Bool {
        left == right || left.hasSuffix("." + right) || right.hasSuffix("." + left)
    }

    private static let protectedDomains = DirectRouteLock.hosts + ["ip123.in", "ipinfo.io", "www.cloudflare.com"]

    private static func option(_ fd: Int32, _ name: Int32) -> Int32? {
        var value: Int32 = 0
        var length = socklen_t(MemoryLayout.size(ofValue: value))
        guard getsockopt(fd, SOL_SOCKET, name, &value, &length) == 0 else { return nil }
        return value
    }

    static func port(_ handle: FileHandle, type: Int32) -> UInt16? {
        let fd = handle.fileDescriptor
        guard option(fd, SO_TYPE) == type, option(fd, SO_REUSEPORT) == 0 else { return nil }
        if type == SOCK_STREAM {
            var tcp = tcp_connection_info()
            var length = socklen_t(MemoryLayout.size(ofValue: tcp))
            guard getsockopt(fd, IPPROTO_TCP, TCP_CONNECTION_INFO, &tcp, &length) == 0,
                  tcp.tcpi_state == TCPS_LISTEN else { return nil }
        } else {
            guard type == SOCK_DGRAM, option(fd, SO_REUSEADDR) == 0 else { return nil }
            var peer = sockaddr_storage()
            var length = socklen_t(MemoryLayout.size(ofValue: peer))
            let result = withUnsafeMutablePointer(to: &peer) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getpeername(fd, $0, &length) }
            }
            guard result == -1, errno == ENOTCONN else { return nil }
        }
        var address = sockaddr_in()
        var length = socklen_t(MemoryLayout.size(ofValue: address))
        let status = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
        }
        let port = UInt16(bigEndian: address.sin_port)
        guard status == 0, length == MemoryLayout<sockaddr_in>.size, address.sin_family == AF_INET,
              address.sin_addr.s_addr == inet_addr("127.0.0.1"), port >= 1024 else { return nil }
        return port
    }
}

private final class DNSLease {
    let names: Set<String>
    let udp: FileHandle
    let tcp: FileHandle
    let key = "State:/Network/Service/" + UUID().uuidString + "/DNS"
    let value: NSDictionary
    var store: SCDynamicStore?

    init?(names: [String], udp: FileHandle, tcp: FileHandle, port: UInt16) {
        self.names = Set(names)
        self.udp = udp
        self.tcp = tcp
        value = [kSCPropNetDNSServerAddresses: ["127.0.0.1"], kSCPropNetDNSServerPort: Int(port),
                 kSCPropNetDNSSupplementalMatchDomains: names, "SupplementalMatchDomainsNoSearch": 1]
        guard let session = SCDynamicStoreCreate(nil, guardServiceName as CFString, nil, nil),
              SCDynamicStoreAddTemporaryValue(session, key as CFString, value) else { return nil }
        store = session
    }

    init?(systemPort port: UInt16, udp: FileHandle, tcp: FileHandle) {
        self.names = []
        self.udp = udp
        self.tcp = tcp
        value = [kSCPropNetDNSServerAddresses: ["127.0.0.1"], kSCPropNetDNSServerPort: Int(port),
                 kSCPropNetDNSSearchOrder: 50000,
                 kSCPropNetDNSSupplementalMatchDomains: [""],
                 kSCPropNetDNSSupplementalMatchOrders: [50000],
                 "SupplementalMatchDomainsNoSearch": 1]
        guard let session = SCDynamicStoreCreate(nil, guardServiceName as CFString, nil, nil),
              SCDynamicStoreAddTemporaryValue(session, key as CFString, value) else { return nil }
        store = session
    }

    var isPublished: Bool {
        guard let store else { return false }
        return value.isEqual(SCDynamicStoreCopyValue(store, key as CFString))
    }

    deinit {
        // Closing only our publishing session relinquishes its temporary value.
        // Keep both socket bindings alive until after closing the session.
        store = nil
        withExtendedLifetime((udp, tcp)) {}
    }
}

// An exported object is allocated per admitted connection. All lease state,
// including disconnection and the timer, is serialized independently of hosts edits.
private final class RuleClient: NSObject, GuardRuleControl {
    let service: RuleService
    weak var peer: NSXPCConnection?
    private var lease: DNSLease?
    private var expiration: ContinuousClock.Instant?
    private var timer: DispatchSourceTimer?
    private var systemLease: DNSLease?
    private var systemExpiration: ContinuousClock.Instant?
    private var systemTimer: DispatchSourceTimer?
    private var ended = false

    init(_ service: RuleService, _ peer: NSXPCConnection) {
        self.service = service
        self.peer = peer
    }

    func disconnect() {
        service.dns.async {
            self.ended = true
            self.clear()
            self.clearSystem()
        }
    }

    private func clear() {
        timer?.cancel()
        timer = nil
        expiration = nil
        if let lease { service.claimed.subtract(lease.names) }
        lease = nil
    }

    private func clearSystem() {
        systemTimer?.cancel()
        systemTimer = nil
        systemExpiration = nil
        if service.systemDNSOwner == ObjectIdentifier(self) {
            service.systemDNSOwner = nil
        }
        systemLease = nil
    }

    private func refresh() {
        expiration = ContinuousClock.now.advanced(by: .seconds(60))
        if timer == nil {
            let source = DispatchSource.makeTimerSource(queue: service.dns)
            source.setEventHandler { [weak self] in
                guard let self, let expiry = self.expiration, ContinuousClock.now >= expiry else { return }
                self.clear()
            }
            // ContinuousClock includes sleep. A periodic uptime timer observes overdue
            // leases immediately after wake without depending on the wall clock.
            source.schedule(deadline: .now() + 1, repeating: .seconds(1), leeway: .milliseconds(100))
            timer = source
            source.activate()
        }
    }

    private func refreshSystem() {
        systemExpiration = ContinuousClock.now.advanced(by: .seconds(60))
        if systemTimer == nil {
            let source = DispatchSource.makeTimerSource(queue: service.dns)
            source.setEventHandler { [weak self] in
                guard let self, let expiry = self.systemExpiration, ContinuousClock.now >= expiry else { return }
                self.clearSystem()
            }
            source.schedule(deadline: .now() + 1, repeating: .seconds(1), leeway: .milliseconds(100))
            systemTimer = source
            source.activate()
        }
    }

    func publishDNS(_ hosts: [String], udp: FileHandle, tcp: FileHandle, withReply reply: @escaping (Bool) -> Void) {
        service.dns.async {
            // Validate before disturbing the current lease. Clear and publish in
            // one queue turn so no competing peer can acquire overlapping names.
            let others = self.service.claimed.subtracting(self.lease?.names ?? [])
            guard !self.ended, self.service.isConsoleUser(self.peer),
                  DNSLeasePolicy.permits(hosts),
                  !hosts.contains(where: { name in others.contains { DNSLeasePolicy.overlaps(name, $0) } }),
                  let port = DNSLeasePolicy.port(udp, type: SOCK_DGRAM),
                  DNSLeasePolicy.port(tcp, type: SOCK_STREAM) == port else { reply(false); return }
            self.clear()
            guard let lease = DNSLease(names: hosts, udp: udp, tcp: tcp, port: port) else { reply(false); return }
            self.lease = lease
            self.service.claimed.formUnion(lease.names)
            self.refresh()
            reply(true)
        }
    }

    func renewDNS(withReply reply: @escaping (Bool) -> Void) {
        service.dns.async {
            guard !self.ended, self.service.isConsoleUser(self.peer), let expiration = self.expiration,
                  ContinuousClock.now < expiration, self.lease?.isPublished == true else {
                self.clear(); reply(false); return
            }
            self.refresh()
            reply(true)
        }
    }

    func clearDNS(withReply reply: @escaping (Bool) -> Void) {
        service.dns.async { self.clear(); reply(true) }
    }

    func publishSystemDNS(_ udp: FileHandle, tcp: FileHandle, withReply reply: @escaping (Bool) -> Void) {
        service.dns.async {
            let me = ObjectIdentifier(self)
            guard !self.ended, self.service.isConsoleUser(self.peer),
                  self.service.systemDNSOwner == nil || self.service.systemDNSOwner == me,
                  let port = DNSLeasePolicy.port(udp, type: SOCK_DGRAM),
                  DNSLeasePolicy.port(tcp, type: SOCK_STREAM) == port else { reply(false); return }
            self.clearSystem()
            guard let lease = DNSLease(systemPort: port, udp: udp, tcp: tcp) else { reply(false); return }
            self.systemLease = lease
            self.service.systemDNSOwner = me
            self.refreshSystem()
            reply(true)
        }
    }

    func renewSystemDNS(withReply reply: @escaping (Bool) -> Void) {
        service.dns.async {
            guard !self.ended, self.service.isConsoleUser(self.peer), let expiration = self.systemExpiration,
                  ContinuousClock.now < expiration, self.systemLease?.isPublished == true else {
                self.clearSystem(); reply(false); return
            }
            self.refreshSystem()
            reply(true)
        }
    }

    func clearSystemDNS(withReply reply: @escaping (Bool) -> Void) {
        service.dns.async { self.clearSystem(); reply(true) }
    }

    func ping(withReply reply: @escaping (Bool) -> Void) {
        reply(service.isConsoleUser(peer))
    }

    func setProtection(_ enabled: Bool, withReply reply: @escaping (Bool) -> Void) {
        service.setProtection(enabled, peer: peer, withReply: reply)
    }
}

// launchd supplies the client requirement from its root-owned plist.
final class RuleService: NSObject, NSXPCListenerDelegate {
    fileprivate let dns = DispatchQueue(label: "local.aiexitguard.rules.dns")
    fileprivate var claimed = Set<String>()
    fileprivate var systemDNSOwner: ObjectIdentifier?
    private let writes = DispatchQueue(label: "local.aiexitguard.rules.write")

    // Accessed only on the serial writes queue.
    private var refreshPending = false

    fileprivate func isConsoleUser(_ connection: NSXPCConnection?) -> Bool {
        var uid: uid_t = 0
        guard let connection, SCDynamicStoreCopyConsoleUser(nil, &uid, nil) != nil,
              uid != 0 else { return false }
        return connection.effectiveUserIdentifier == uid
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection peer: NSXPCConnection) -> Bool {
        guard isConsoleUser(peer) else { return false }
        let client = RuleClient(self, peer)
        peer.exportedInterface = guardRuleInterface()
        peer.exportedObject = client
        peer.interruptionHandler = { client.disconnect() }
        peer.invalidationHandler = { client.disconnect() }
        peer.resume()
        return true
    }

    func setProtection(_ enabled: Bool, peer: NSXPCConnection?, withReply reply: @escaping (Bool) -> Void) {
        writes.async {
            guard self.isConsoleUser(peer) else { reply(false); return }
            let args = ["-e", DirectRouteLock.editor, "--", "/private/etc",
                        enabled ? "on" : "off", DirectRouteLock.block, DirectRouteLock.legacyBlock]
            let output = Pipe()
            guard self.run("/usr/bin/perl", args, output: output.fileHandleForWriting) else { reply(false); return }
            output.fileHandleForWriting.closeFile()
            let change = output.fileHandleForReading.readDataToEndOfFile()
            guard change.isEmpty || change == Data("changed\n".utf8) else { reply(false); return }
            if !change.isEmpty { self.refreshPending = true }
            if self.refreshPending {
                guard self.run("/usr/bin/dscacheutil", ["-flushcache"]),
                      self.run("/usr/bin/killall", ["-HUP", "mDNSResponder"]) else { reply(false); return }
                self.refreshPending = false
            }
            reply(DirectRouteLock.read() == (enabled ? .on : .off))
        }
    }

    private func run(_ executable: String, _ arguments: [String], output: FileHandle = .nullDevice) -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        process.currentDirectoryURL = URL(fileURLWithPath: "/")
        process.arguments = arguments
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            process.waitUntilExit()
            return process.terminationStatus == 0
        } catch { return false }
    }
}

if CommandLine.arguments == [CommandLine.arguments[0],"--upgrade-hosts"], geteuid()==0 {
    let task=Process();task.executableURL=URL(fileURLWithPath:"/usr/bin/perl")
    task.arguments=["-e",DirectRouteLock.editor,"--","/private/etc","upgrade",DirectRouteLock.block,DirectRouteLock.legacyBlock]
    task.environment=["PATH":"/usr/bin:/bin"];try task.run();task.waitUntilExit();exit(task.terminationStatus)
}
guard geteuid() == 0, CommandLine.arguments.count == 2 else { exit(1) }
let listener = NSXPCListener(machServiceName: guardServiceName)
listener.setConnectionCodeSigningRequirement(CommandLine.arguments[1])
let service = RuleService()
listener.delegate = service
listener.resume()
RunLoop.main.run()
