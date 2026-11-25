// Compiled with the helper by test_dns_lease.py. Never linked into the installed helper.
private final class MockStore {
    static var values: [String: NSDictionary] = [:] // serialized on RuleService.dns
    var key: String?

    func add(_ key: String, _ value: NSDictionary) -> Bool {
        guard Self.values[key] == nil else { return false }
        let incoming = value["SupplementalMatchDomains"] as! [String]
        for published in Self.values.values {
            let previous = published["SupplementalMatchDomains"] as! [String]
            assert(!incoming.contains { name in previous.contains { DNSLeasePolicy.overlaps(name, $0) } })
        }
        self.key = key
        Self.values[key] = value
        return true
    }

    deinit {
        if let key { Self.values.removeValue(forKey: key) }
    }
}

private let service = RuleService()
private let listener = NSXPCListener.anonymous()
listener.delegate = service
listener.resume()

private func connect() -> (NSXPCConnection, GuardRuleControl) {
    let connection = NSXPCConnection(listenerEndpoint: listener.endpoint)
    connection.remoteObjectInterface = guardRuleInterface()
    connection.resume()
    let proxy = connection.synchronousRemoteObjectProxyWithErrorHandler { error in
        fatalError("XPC failed: \(error)")
    } as! GuardRuleControl
    return (connection, proxy)
}

private func call(_ body: (@escaping (Bool) -> Void) -> Void) -> Bool {
    var result: Bool?
    body { result = $0 }
    return result!
}

private func bound(_ type: Int32, _ port: UInt16 = 0, address: String = "127.0.0.1") -> FileHandle? {
    let fd = socket(AF_INET, type, 0)
    precondition(fd >= 0)
    var addr = sockaddr_in()
    addr.sin_len = UInt8(MemoryLayout.size(ofValue: addr))
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_addr.s_addr = inet_addr(address)
    addr.sin_port = port.bigEndian
    let length = socklen_t(addr.sin_len)
    let ok = withUnsafePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, length) }
    }
    guard ok == 0 else { close(fd); return nil }
    return FileHandle(fileDescriptor: fd, closeOnDealloc: true)
}

private func sockets() -> (FileHandle, FileHandle, UInt16) {
    for _ in 0..<50 {
        let udp = bound(SOCK_DGRAM)!
        let port = DNSLeasePolicy.port(udp, type: SOCK_DGRAM)!
        if let tcp = bound(SOCK_STREAM, port) {
            precondition(DNSLeasePolicy.port(tcp, type: SOCK_STREAM) == nil)
            precondition(listen(tcp.fileDescriptor, 2) == 0)
            return (udp, tcp, port)
        }
    }
    fatalError("Could not allocate fixture sockets")
}

private func values() -> [String: NSDictionary] {
    service.dns.sync { MockStore.values }
}

let names = ["mcp.linear.app", "mcp.figma.com"]
assert(!DNSLeasePolicy.permits([]))
assert(!DNSLeasePolicy.permits(["mcp.figma.com", "mcp.figma.com"]))
assert(!DNSLeasePolicy.permits(Array(DNSLeasePolicy.hosts.prefix(11))))
assert(!DNSLeasePolicy.permits(["local", "figma.com"]))
assert(DNSLeasePolicy.port(bound(SOCK_DGRAM, address: "0.0.0.0")!, type: SOCK_DGRAM) == nil)
let reusable = bound(SOCK_DGRAM)!
var on: Int32 = 1
assert(setsockopt(reusable.fileDescriptor, SOL_SOCKET, SO_REUSEADDR, &on, socklen_t(MemoryLayout<Int32>.size)) == 0)
assert(DNSLeasePolicy.port(reusable, type: SOCK_DGRAM) == nil)
let reusableTCP = bound(SOCK_STREAM)!
assert(listen(reusableTCP.fileDescriptor, 2) == 0)
assert(setsockopt(reusableTCP.fileDescriptor, SOL_SOCKET, SO_REUSEPORT, &on, socklen_t(MemoryLayout<Int32>.size)) == 0)
assert(DNSLeasePolicy.port(reusableTCP, type: SOCK_STREAM) == nil)
let (client, first) = connect()
let (otherClient, other) = connect()
let (udp, tcp, port) = sockets()
let (u2, t2, _) = sockets()
assert(!call { first.publishDNS(names, udp: udp, tcp: t2, withReply: $0) })
assert(!call { first.publishDNS(names, udp: tcp, tcp: udp, withReply: $0) })
assert(!call { first.publishDNS(["not.in.catalog"], udp: udp, tcp: tcp, withReply: $0) })
assert(call { first.publishDNS(names, udp: udp, tcp: tcp, withReply: $0) })
let originalKey = values().keys.first!
assert(originalKey.hasPrefix("State:/Network/Service/") && originalKey.hasSuffix("/DNS"))
assert(values()[originalKey] == ["ServerAddresses": ["127.0.0.1"], "ServerPort": Int(port),
                         "SupplementalMatchDomains": names, "SupplementalMatchDomainsNoSearch": 1])
for name in ["api.openai.com", "internal.ipinfo.io", "cloudflare.com"] {
    assert(DNSLeasePolicy.hosts.contains(name) && !DNSLeasePolicy.permits([name]))
}
assert(call { other.publishDNS(["mcp.stripe.com"], udp: u2, tcp: t2, withReply: $0) })
assert(!call { first.publishDNS(["mcp.linear.app", "mcp.stripe.com"], udp: udp, tcp: tcp, withReply: $0) })
assert(values()[originalKey] != nil && values().count == 2)
let replacement = ["mcp.linear.app", "mcp.sentry.dev"]
assert(call { first.publishDNS(replacement, udp: udp, tcp: tcp, withReply: $0) })
let key = values().first { $0.value["SupplementalMatchDomains"] as? [String] == replacement }!.key
assert(values()[originalKey] == nil && values().count == 2)
assert(!call { other.publishDNS(["fixture.mcp.linear.app"], udp: u2, tcp: t2, withReply: $0) })
assert(call { other.publishDNS(["mcp.figma.com"], udp: u2, tcp: t2, withReply: $0) })
udp.closeFile()
tcp.closeFile()
assert(bound(SOCK_DGRAM, port) == nil && bound(SOCK_STREAM, port) == nil)
assert(!call { other.publishDNS(names, udp: u2, tcp: t2, withReply: $0) })
assert(call(other.clearDNS) && values().count == 1)
assert(call { other.publishDNS(["mcp.stripe.com"], udp: u2, tcp: t2, withReply: $0) })
assert(call(first.renewDNS))
client.invalidate()
for _ in 0..<100 where values()[key] != nil { usleep(10000) }
assert(values()[key] == nil && values().count == 1)
assert(bound(SOCK_DGRAM, port) != nil && bound(SOCK_STREAM, port) != nil)
assert(call(other.clearDNS) && values().isEmpty)
assert(call { other.publishDNS(["mcp.stripe.com"], udp: u2, tcp: t2, withReply: $0) })
assert(call(other.renewDNS))
Thread.sleep(forTimeInterval: 3.5)
assert(values().isEmpty && !call(other.renewDNS))
// Verify system-wide DoT DNS lease: single owner, renewal, clear, and expiry.
let (su1, st1, sp1) = sockets()
let (su2, st2, _) = sockets()
assert(call { other.publishSystemDNS(su1, tcp: st1, withReply: $0) })
let sysKey = values().keys.first!
assert(values()[sysKey] == ["ServerAddresses": ["127.0.0.1"], "ServerPort": Int(sp1),
                            "SearchOrder": 50000,
                            "SupplementalMatchDomains": [""],
                            "SupplementalMatchOrders": [50000],
                            "SupplementalMatchDomainsNoSearch": 1])
assert(call(other.renewSystemDNS))
let (thirdClient, third) = connect()
assert(!call { third.publishSystemDNS(su2, tcp: st2, withReply: $0) })
assert(call(other.clearSystemDNS) && values().isEmpty)
assert(call { third.publishSystemDNS(su2, tcp: st2, withReply: $0) })
thirdClient.invalidate()
for _ in 0..<100 where !values().isEmpty { usleep(10000) }
assert(values().isEmpty)
otherClient.invalidate()
print("Passed XPC publication, host replacement, protected domains, socket ownership, peer isolation, disconnect and expiry")

private var menuConnections = 0
func fixtureMenuConnection() -> NSXPCConnection {
    menuConnections += 1
    return NSXPCConnection(listenerEndpoint: listener.endpoint)
}
func fixtureWorkerURL() -> URL? { URL(fileURLWithPath: CommandLine.arguments[1]) }
private let workerPath = CommandLine.arguments[1]
private let monitor = MCPDNSMonitor()
private var reports: [[String]] = []
monitor.changed = { hosts in
    reports.append(hosts)
    switch reports.count {
    case 1:
        assert(hosts == names)
        FileManager.default.createFile(atPath: workerPath + ".replace", contents: nil)
    case 2:
        assert(hosts == replacement && menuConnections == 1)
        FileManager.default.createFile(atPath: workerPath + ".corrupt", contents: nil)
    case 3: assert(hosts.isEmpty)
    default: assertionFailure("Unexpected menu status")
    }
}
monitor.start()
let deadline = Date().addingTimeInterval(8)
while !FileManager.default.fileExists(atPath: workerPath + ".restarted") && Date() < deadline {
    RunLoop.main.run(until: Date().addingTimeInterval(0.02))
}
assert(FileManager.default.fileExists(atPath: workerPath + ".restarted"))
assert(reports == [names, replacement, []] && menuConnections == 1 && values().isEmpty)
monitor.stop()
print("Passed menu update on one peer, malformed worker output withdrawal and restart")
