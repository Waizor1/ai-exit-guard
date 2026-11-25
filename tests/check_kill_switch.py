"""Exercise the exact hosts transaction used by the system helper in a private directory."""
import concurrent.futures
import os
import pathlib
import re
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
source = (root / 'GuardRules.swift').read_text()
program = source.split('static let editor = #"""\n', 1)[1].split('\n"""#', 1)[0]
names = re.findall(r'"([\w.-]+)"', source.split('static let hosts = [', 1)[1].split(']', 1)[0])
begin, end = (re.search('static let '+k+r' = "(.+)"', source)[1] for k in ('begin','end'))
block = '\n'.join([begin, *('127.0.0.2 '+h for h in names), *('::ffff:127.0.0.2 '+h for h in names), end, ''])
assert {'api.anthropic.com','chatgpt.com','api.openai.com','claude.ai'} <= set(names)
with tempfile.TemporaryDirectory() as directory:
    hosts = pathlib.Path(directory)/'hosts'
    original = b'127.0.0.1 localhost\n# custom\n192.0.2.17 example.test\n'
    hosts.write_bytes(original)
    hosts.chmod(0o640)
    legacy = begin + '\n127.0.0.2 legacy.test\n' + end + '\n'
    def change(mode):
        return subprocess.run(['/usr/bin/perl','-e',program,'--',directory,mode,block,legacy],capture_output=True)
    def applied(mode):
        result = change(mode)
        assert result.returncode == 0, result.stderr
        return result.stdout
    assert applied('upgrade') == b''
    with concurrent.futures.ThreadPoolExecutor() as pool:
        assert sorted(pool.map(applied,['on']*4)) == [b'', b'', b'', b'changed\n']
    assert hosts.read_bytes() == original+block.encode()
    assert hosts.stat().st_mode & 0o777 == 0o640
    assert applied('upgrade') == b''
    assert applied('off') == b'changed\n' and applied('off') == b''
    assert hosts.read_bytes() == original
    hosts.write_bytes(original + legacy.encode())
    assert applied('upgrade') == b'changed\n' and hosts.read_bytes() == original + block.encode()
    assert applied('upgrade') == b''
    for damaged in (original+begin.encode()+b'\n',original+b'10.0.0.3 Api.Anthropic.Com\n'):
        hosts.write_bytes(damaged)
        result = change('on')
        assert result.returncode != 0 and result.stdout == b'' and hosts.read_bytes() == damaged
    # Exercise the installer's actual branching with private stand-ins for system tools.
    folder = pathlib.Path(directory)
    installer = (root/'packaging/installer/postinstall').read_text()
    log = folder/'refresh.log'
    pending = folder/'dns-refresh-pending'
    marker_path = '/private/var/db/local.aiexitguard.dns-refresh-pending'
    assert marker_path in installer
    installer = installer.replace(marker_path, str(pending))
    replacements = {
        '/bin/launchctl': 'exit 0',
        '/Library/PrivilegedHelperTools/local.aiexitguard.rules': 'printf "%s" "$REPORT"; exit "$CODE"',
        '/usr/bin/dscacheutil': 'echo "dscacheutil $*" >> "$LOG"; test "$FAIL" != flush',
        '/usr/bin/killall': 'echo "killall $*" >> "$LOG"; test "$FAIL" != hup',
    }
    for command, script in replacements.items():
        stub = folder/pathlib.Path(command).name
        stub.write_text('#!/bin/sh\n' + script + '\n')
        stub.chmod(0o700)
        assert command in installer
        installer = installer.replace(command, str(stub))
    flush = ['dscacheutil -flushcache']
    both = flush + ['killall -HUP mDNSResponder']
    for report, code, fail, success, refreshes, still_pending in [
        ('', 0, '', True, [], False),
        ('changed\n', 0, 'flush', False, flush, True),
        ('', 0, 'hup', False, both, True),
        ('', 0, '', True, both, False),
        ('', 0, '', True, [], False),
        ('changed\n', 0, '', True, both, False),
        ('', 1, '', False, [], False),
        ('unexpected', 0, '', False, [], False),
    ]:
        log.write_text('')
        env = dict(os.environ, LOG=str(log), REPORT=report, CODE=str(code), FAIL=fail)
        result = subprocess.run(['/bin/sh','-c',installer], env=env)
        assert (result.returncode == 0) == success and log.read_text().splitlines() == refreshes
        assert pending.exists() == still_pending
        if still_pending:
            assert pending.is_dir() and pending.stat().st_mode & 0o777 == 0o700
print('Passed hosts transactions, concurrent no-ops, upgrade refresh and conflict checks.')
