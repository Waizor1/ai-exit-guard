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
if sys.argv[2:] == ['--developer-id']:
    team = re.search(r'^TeamIdentifier=([A-Z0-9]{10})$', info, re.M)
    if not team:
        raise RuntimeError('A Developer ID Application signature is required')
    # Match Guard from the same Apple developer team across version and certificate renewals.
    requirement = ('identifier "local.aiexitguard.menu" and anchor apple generic '
                   'and certificate 1[field.1.2.840.113635.100.6.2.6] exists '
                   'and certificate leaf[field.1.2.840.113635.100.6.1.13] exists '
                   f'and certificate leaf[subject.OU] = "{team[1]}"')
elif len(sys.argv) == 4 and sys.argv[2] == '--local-cert' and re.fullmatch(r'[a-fA-F0-9]{40}', sys.argv[3]):
    requirement = f'identifier "local.aiexitguard.menu" and certificate leaf = H"{sys.argv[3]}"'
elif sys.argv[2:]:
    raise ValueError('Unknown signing mode')
subprocess.run(['/usr/bin/codesign', '--verify', '--all-architectures', '-R', '=' + requirement, app], check=True)
plist = root / f'Library/LaunchDaemons/{service}.plist'
plist.parent.mkdir(parents=True, exist_ok=True)
plist.write_bytes(plistlib.dumps({
    'Label': service, 'ProgramArguments': [f'/Library/PrivilegedHelperTools/{service}', requirement],
    'MachServices': {service: True}, 'ProcessType': 'Background',
}))

ingress = 'local.aiexitguard.ingress'
(plist.parent / (ingress+'.plist')).write_bytes(plistlib.dumps({
    'Label': ingress, 'ProgramArguments': ['/Library/PrivilegedHelperTools/'+ingress,'ingress-bootstrap'],
    'KeepAlive': True, 'ThrottleInterval': 30, 'ProcessType': 'Background',
}))
