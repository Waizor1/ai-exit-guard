"""Generate root-owned launchd configuration from the finished universal menu."""
import pathlib
import plistlib
import re
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
app = root / 'Applications/AI Exit Guard.app'
service = 'local.aiexitguard.rules'
hashes = []
for arch in ('arm64', 'x86_64'):
    info = subprocess.check_output(['/usr/bin/codesign', '-d', '--arch', arch, '-vvv', app],
                                   stderr=subprocess.STDOUT, text=True)
    hashes.append(re.search(r'^CDHash=([0-9a-f]{40})$', info, re.M)[1])
    if 'runtime' not in re.search(r'^CodeDirectory .+$', info, re.M)[0]:
        raise RuntimeError('Client must use hardened runtime')
requirement = 'identifier "local.aiexitguard.menu" and (' + ' or '.join(
    f'cdhash H"{digest}"' for digest in hashes) + ')'
subprocess.run(['/usr/bin/codesign', '--verify', '--all-architectures', '-R', '=' + requirement, app], check=True)
plist = root / f'Library/LaunchDaemons/{service}.plist'
plist.parent.mkdir(parents=True, exist_ok=True)
plist.write_bytes(plistlib.dumps({
    'Label': service, 'ProgramArguments': [f'/Library/PrivilegedHelperTools/{service}', requirement],
    'MachServices': {service: True}, 'ProcessType': 'Background',
}))
