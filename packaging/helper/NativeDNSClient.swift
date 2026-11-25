// Compile as main.swift in the isolated native DNS integration fixture.
import Foundation

guard CommandLine.arguments.count == 4,
      let udp = Int32(CommandLine.arguments[2]), let tcp = Int32(CommandLine.arguments[3]) else { exit(1) }
let connection = NSXPCConnection(machServiceName: guardServiceName, options: .privileged)
connection.remoteObjectInterface = guardRuleInterface()
connection.resume()
let proxy = connection.synchronousRemoteObjectProxyWithErrorHandler { error in
    FileHandle.standardError.write(Data("fixture XPC failed: \(error.localizedDescription)\n".utf8))
    exit(2)
} as! GuardRuleControl
proxy.publishDNS([CommandLine.arguments[1]], udp: FileHandle(fileDescriptor: udp),
                 tcp: FileHandle(fileDescriptor: tcp)) { ok in
    guard ok else {
        FileHandle.standardError.write(Data("publishDNS rejected fixture sockets, name, or configd publication\n".utf8))
        exit(3)
    }
}
print("published")
fflush(stdout)
while let command = readLine() {
    if command == "clear" {
        proxy.clearDNS { ok in print(ok ? "cleared" : "clear failed"); fflush(stdout) }
    } else if command == "renew" {
        proxy.renewDNS { ok in print(ok ? "renewed" : "renew failed"); fflush(stdout) }
    }
}
connection.invalidate()
