import Foundation
import Darwin

enum SystemDNSState: Equatable {
    case off
    case starting
    case active(String)
    case unavailable

    var label: String {
        switch self {
        case .off: return "Выключен"
        case .starting: return "Подключаем DoT…"
        case .active(let upstream): return upstream.isEmpty ? "Включён (DoT)" : "Работает · \(upstream)"
        case .unavailable: return "DoT недоступен в этой сети"
        }
    }
}

private struct SystemDNSReport: Decodable {
    let ready: Bool
    let upstream: String?
}

// Owns the loopback sockets, the unprivileged DoT worker, and the temporary
// system-wide Supplemental DNS lease in configd.
final class SystemDNSMonitor {
    var changed: (SystemDNSState) -> Void = { _ in }
    private var worker: Process?
    private var connection: NSXPCConnection?
    private var handles: (FileHandle, FileHandle)?
    private var published = false
    private var state: SystemDNSState = .off
    private var epoch = UUID()
    private var operation: UUID?
    private var retry: DispatchWorkItem?
    private var enabled = false

    private func report(_ next: SystemDNSState) {
        guard state != next else { return }
        state = next
        changed(next)
    }

    private func bindLoopback(_ type: Int32, port: in_port_t) -> (FileHandle, in_port_t)? {
        let fd = socket(AF_INET, type, 0)
        guard fd >= 0 else { return nil }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        guard fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 else { return nil }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        var size = socklen_t(MemoryLayout.size(ofValue: address))
        let ok = withUnsafeMutablePointer(to: &address) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, size) == 0 && getsockname(fd, $0, &size) == 0
            }
        }
        guard ok, type != SOCK_STREAM || listen(fd, 32) == 0 else { return nil }
        return (handle, address.sin_port)
    }

    func start() {
        enabled = true
        guard worker == nil,
              let binary = Bundle.main.url(forResource: "guard", withExtension: nil) else { return }
        var pair: (FileHandle, FileHandle)?
        for _ in 0..<5 {
            if let (tcp, port) = bindLoopback(SOCK_STREAM, port: 0),
               let (udp, _) = bindLoopback(SOCK_DGRAM, port: port) {
                pair = (udp, tcp)
                break
            }
        }
        guard let pair else { scheduleRetry(); return }
        let process = Process(), pipe = Pipe(), generation = UUID()
        epoch = generation
        process.executableURL = binary
        process.arguments = ["system-dns"]
        process.environment = ["HOME": FileManager.default.homeDirectoryForCurrentUser.path,
                               "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        process.standardInput = pair.0
        process.standardOutput = pair.1
        process.standardError = pipe
        process.terminationHandler = { [weak self] _ in
            DispatchQueue.main.async {
                guard let self, self.epoch == generation else { return }
                self.reset(reportOff: false)
                self.scheduleRetry()
            }
        }
        do { try process.run() } catch { scheduleRetry(); return }
        handles = pair
        worker = process
        report(.starting)
        DispatchQueue.global(qos: .utility).async { [weak self] in
            defer {
                DispatchQueue.main.async {
                    guard let self, self.epoch == generation else { return }
                    self.reset(reportOff: false)
                    self.scheduleRetry()
                }
            }
            var buffer = Data()
            var bytes = [UInt8](repeating: 0, count: 4096)
            while true {
                let count = Darwin.read(pipe.fileHandleForReading.fileDescriptor, &bytes, bytes.count)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { return }
                buffer.append(bytes, count: count)
                guard buffer.count < 8192 else { return }
                while let end = buffer.firstIndex(of: 10) {
                    let line = buffer.prefix(upTo: end)
                    guard let status = try? JSONDecoder().decode(SystemDNSReport.self, from: line) else { return }
                    buffer.removeSubrange(...end)
                    DispatchQueue.main.async {
                        guard let self, self.epoch == generation else { return }
                        self.apply(status)
                    }
                }
            }
        }
    }

    private func apply(_ status: SystemDNSReport) {
        guard let handles else { return }
        if !status.ready {
            if connection != nil {
                withdraw(nextState: .unavailable)
            } else {
                report(.unavailable)
            }
            return
        }
        let renew = operation == nil && published && connection != nil
        let client: NSXPCConnection
        if let connection { client = connection }
        else {
            client = NSXPCConnection(machServiceName: guardServiceName, options: .privileged)
            client.remoteObjectInterface = guardRuleInterface()
            let lost: () -> Void = { [weak self, weak client] in
                DispatchQueue.main.async {
                    if let self, let client, self.connection === client {
                        self.withdraw(nextState: self.enabled ? .unavailable : .off)
                    }
                }
            }
            client.invalidationHandler = lost
            client.interruptionHandler = lost
            connection = client
            client.resume()
        }
        let token = UUID()
        operation = token
        let upstream = status.upstream ?? ""
        let reply: (Bool) -> Void = { [weak self] ok in
            DispatchQueue.main.async {
                guard let self, self.operation == token else { return }
                self.operation = nil
                if ok {
                    self.published = true
                    self.report(.active(upstream))
                } else {
                    self.withdraw(nextState: self.enabled ? .unavailable : .off)
                }
            }
        }
        guard let remote = client.remoteObjectProxyWithErrorHandler({ _ in reply(false) }) as? GuardRuleControl else {
            withdraw(nextState: enabled ? .unavailable : .off)
            return
        }
        if renew { remote.renewSystemDNS(withReply: reply) }
        else { remote.publishSystemDNS(handles.0, tcp: handles.1, withReply: reply) }
        DispatchQueue.main.asyncAfter(deadline: .now() + 5) { [weak self] in
            if self?.operation == token {
                self?.withdraw(nextState: self?.enabled == true ? .unavailable : .off)
            }
        }
    }

    private func withdraw(nextState: SystemDNSState) {
        operation = nil
        published = false
        let old = connection
        connection = nil
        old?.invalidate()
        report(nextState)
    }

    private func scheduleRetry() {
        retry?.cancel()
        guard enabled else { report(.off); return }
        report(.unavailable)
        let work = DispatchWorkItem { [weak self] in self?.start() }
        retry = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 15, execute: work)
    }

    private func reset(reportOff: Bool) {
        epoch = UUID()
        withdraw(nextState: reportOff ? .off : .unavailable)
        if let worker, worker.isRunning { worker.terminate() }
        worker = nil
        handles = nil
        retry?.cancel()
        retry = nil
    }

    func stop() {
        enabled = false
        reset(reportOff: true)
    }
}
