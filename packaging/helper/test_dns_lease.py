"""Test the real XPC wire and socket leases with an in-memory replacement for configd."""
from pathlib import Path
import subprocess
import tempfile

here = Path(__file__).resolve().parent
root = here.parents[1]
helper = (here / 'main.swift').read_text().split('if CommandLine.arguments ==')[0]
# Simulate the registry acquiring names that overlap protected routes.
helper = helper.replace('= embeddedMCPHosts', '= embeddedMCPHosts.union(["api.openai.com", "internal.ipinfo.io", "cloudflare.com", "fixture.mcp.linear.app"])')
helper = helper.replace('SCDynamicStoreCreate(nil, guardServiceName as CFString, nil, nil)', 'MockStore() as MockStore?')
helper = helper.replace('SCDynamicStoreAddTemporaryValue(session, key as CFString, value)', 'session.add(key, value)')
helper = helper.replace('SCDynamicStoreCopyValue(store, key as CFString)', 'MockStore.values[key]')
helper = helper.replace('var store: SCDynamicStore?', 'var store: MockStore?')
helper = helper.replace('guard let store else', 'guard store != nil else')
assert 'SCDynamicStoreAddTemporaryValue' not in helper
helper = helper.replace('.advanced(by: .seconds(60))', '.advanced(by: .seconds(2))')
start = helper.index('        var uid: uid_t = 0')
end = helper.index('\n    }', start)
helper = helper[:start] + '        connection != nil' + helper[end:]

with tempfile.TemporaryDirectory() as tmp:
    from catalog_source import emit
    catalog = Path(tmp) / 'MCPCatalog.swift'
    emit(catalog)
    main = Path(tmp) / 'main.swift'
    main.write_text(helper + (here / 'DNSLeaseFixture.swift').read_text())
    # Drive the menu through the real worker pipe and anonymous XPC transport.
    monitor = Path(tmp) / 'MCPDNS.swift'
    source = (root / 'MCPDNS.swift').read_text()
    source = source.replace('NSXPCConnection(machServiceName:guardServiceName,options:.privileged)', 'fixtureMenuConnection()')
    source = source.replace('Bundle.main.url(forResource: "guard", withExtension: nil)', 'fixtureWorkerURL()')
    monitor.write_text(source.replace('.now()+30,execute:work', '.now()+0.05,execute:work'))
    worker = Path(tmp) / 'guard'
    worker.write_text("""#!/bin/sh
set -eu
if test -f "$0.started"; then
    touch "$0.restarted"
    exec /bin/sleep 20
fi
touch "$0.started"
echo '["mcp.linear.app","mcp.figma.com"]' >&2
while ! test -f "$0.replace"; do /bin/sleep 0.05; done
echo '["mcp.linear.app","mcp.sentry.dev"]' >&2
while ! test -f "$0.corrupt"; do /bin/sleep 0.05; done
echo '{malformed' >&2
exec /bin/sleep 20
""")
    worker.chmod(0o700)
    binary = Path(tmp) / 'dns-test'
    subprocess.run(['xcrun','swiftc',root / 'GuardRules.swift', catalog, monitor, main,'-o', binary],check=True)
    subprocess.run([binary, worker], check=True, timeout=25)
