"""Exercise NSXPC peer admission under the console user's launchd namespace."""
import os
import pathlib
import plistlib
import re
import subprocess
import tempfile
import uuid

root = pathlib.Path(__file__).resolve().parents[1]
label = 'local.aiexitguard.test.' + uuid.uuid4().hex
domain = f'gui/{os.getuid()}'
assert os.getuid() != 0

def run(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, **kwargs)

with tempfile.TemporaryDirectory() as tmp:
    folder = pathlib.Path(tmp)
    shared = folder / 'GuardRules.swift'
    hosts = folder/'hosts'
    original_hosts = b'127.0.0.1 localhost\n192.0.2.23 intranet.test\n'
    hosts.write_bytes(original_hosts)
    shared.write_text((root/'GuardRules.swift').read_text().replace('local.aiexitguard.rules', label)
                      .replace('/private/etc/hosts', str(hosts)))
    source = folder / 'main.swift'
    # Redirect the editor to the fixture and skip machine-wide cache flushes.
    original = (root/'packaging/helper/main.swift').read_text()
    assert original.count('geteuid() == 0') == 1
    source.write_text(original.replace('geteuid() == 0', 'geteuid() != 0').replace('"/private/etc"', f'"{folder}"')
                      .replace('"/usr/bin/dscacheutil"', '"/usr/bin/true"').replace('"/usr/bin/killall"', '"/usr/bin/true"'))
    daemon = folder/'service'
    run('xcrun','swiftc',shared,source,'-o',daemon)
    ping = """
import Foundation
let connection = NSXPCConnection(machServiceName: guardServiceName)
connection.remoteObjectInterface = NSXPCInterface(with: GuardRuleControl.self)
connection.resume()
let proxy = connection.remoteObjectProxyWithErrorHandler { _ in exit(7) } as? GuardRuleControl
if CommandLine.arguments.count > 1 {
    proxy?.setProtection(CommandLine.arguments[1] == "on") { ok in exit(ok ? 0 : 8) }
} else {
    proxy?.ping { ok in exit(ok ? 0 : 8) }
}
DispatchQueue.main.asyncAfter(deadline: .now() + 6) { exit(9) }
RunLoop.main.run()
"""
    clients = [folder/'accepted',folder/'unrelated']
    for index, binary in enumerate(clients):
        source.write_text(ping + f'\nprint({index})\n')
        run('xcrun','swiftc',shared,source,'-o',binary)
        run('codesign','--force','--options','runtime','--identifier','local.aiexitguard.menu','-s','-',binary)
    info = run('codesign','-d','-vvv',clients[0]).stderr
    digest = re.search(r'^CDHash=([0-9a-f]{40})$', info, re.M)[1]
    requirement = f'identifier "local.aiexitguard.menu" and cdhash H"{digest}"'
    plist = folder/'service.plist'
    plist.write_bytes(plistlib.dumps({'Label':label, 'ProgramArguments':[str(daemon),requirement],
                                      'MachServices':{label:True}}))
    run('launchctl','bootstrap',domain,plist)
    try:
        run(clients[0],timeout=10)
        run(clients[0], 'on', timeout=10)
        protected = hosts.read_bytes()
        assert protected.startswith(original_hosts) and b'127.0.0.2 api.openai.com\n' in protected
        denied = subprocess.run([clients[1], 'off'],timeout=10)
        assert denied.returncode == 7, denied.returncode
        assert hosts.read_bytes() == protected
        run(clients[0], 'off', timeout=10)
        assert hosts.read_bytes() == original_hosts
        print('NSXPC: pinned GUI enabled and disabled the isolated rule; unrelated client rejected; hosts restored byte-for-byte.')
    finally:
        run('launchctl','bootout',f'{domain}/{label}')
