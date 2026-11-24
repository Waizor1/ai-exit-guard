"""Exercise the exact hosts transaction used by the system helper in a private directory."""
import concurrent.futures
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
    def change(mode):
        return subprocess.run(['/usr/bin/perl','-e',program,'--',directory,mode,block],capture_output=True).returncode
    with concurrent.futures.ThreadPoolExecutor() as pool:
        assert list(pool.map(change,['on']*4)) == [0]*4
    assert hosts.read_bytes() == original+block.encode()
    assert hosts.stat().st_mode & 0o777 == 0o640
    assert change('off') == change('off') == 0
    assert hosts.read_bytes() == original
    for damaged in (original+begin.encode()+b'\n',original+b'10.0.0.3 Api.Anthropic.Com\n'):
        hosts.write_bytes(damaged)
        assert change('on') != 0 and hosts.read_bytes() == damaged
print('Passed parallel activation, opt-out, both address families, conflict handling and preservation of unrelated records.')
