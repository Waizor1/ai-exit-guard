"""Test the real XPC wire and socket leases with an in-memory replacement for configd."""
from pathlib import Path
import re
import subprocess
import tempfile

here = Path(__file__).resolve().parent
root = here.parents[1]
helper = (here / 'main.swift').read_text().split('if CommandLine.arguments ==')[0]
catalog = [line.split('\t')[0] for line in (root / 'internal/mcpdns/catalog.tsv').read_text().splitlines() if not line.startswith('#')]
swift_names = helper.split('static let hosts: Set<String> = [')[1].split(']')[0]
assert catalog == sorted(set(catalog)) == re.findall(r'"([^"]+)"', swift_names) and 20 <= len(catalog) <= 4096

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
    main = Path(tmp) / 'main.swift'
    main.write_text(helper + (here / 'DNSLeaseFixture.swift').read_text())
    binary = Path(tmp) / 'dns-test'
    subprocess.run(['xcrun','swiftc',root / 'GuardRules.swift', main,'-o', binary],check=True)
    subprocess.run([binary], check=True, timeout=25)
