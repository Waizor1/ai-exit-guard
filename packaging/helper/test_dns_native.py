"""macOS integration test. Run as an ordinary user on a disposable passwordless-sudo CI Mac.

Two unique .test names are the complete allowlist of a separate fixture helper. All
publication, socket validation and disconnect handling use the production code. A
pinned fixture UID replaces console-user discovery so headless CI can exercise DNS.
--compile-only builds and signs locally without sudo or changing any network state.
"""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import plistlib
import re
import select
import socket
import subprocess
import sys
import tempfile
import time
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
ANSWER = '192.0.2.17'


def run(*args, **kwargs):
    try:
        return subprocess.run(args, text=True, check=True, capture_output=True, timeout=120, **kwargs)
    except subprocess.CalledProcessError as error:
        raise RuntimeError(f'{args[0]} failed: {error.stderr.strip()}') from error


def build(folder, label, names):
    rules = folder / 'GuardRules.swift'
    rules.write_text((ROOT / 'GuardRules.swift').read_text().replace('local.aiexitguard.rules', label))
    main = folder / 'main.swift'
    source = (HERE / 'main.swift').read_text()
    start = source.index('    static let hosts: Set<String> = ')
    end = source.index('\n\n    static func permits', start)
    source = source[:start] + '    static let hosts: Set<String> = ["' + '", "'.join(names) + '"]' + source[end:]
    start = source.index('        var uid: uid_t = 0')
    end = source.index('\n    }', start)
    main.write_text(source[:start] + f'        connection?.effectiveUserIdentifier == {os.getuid()}' + source[end:])
    service = folder / 'helper'
    run('xcrun', 'swiftc', rules, main, '-o', service)
    main.write_text((HERE / 'NativeDNSClient.swift').read_text())
    client = folder / 'client'
    run('xcrun', 'swiftc', rules, main, '-o', client)
    identifier = label + '.client'
    run('/usr/bin/codesign', '--force', '--options', 'runtime', '--identifier', identifier, '-s', '-', client)
    digest = re.search(r'^CDHash=([0-9a-f]{40})$', run('/usr/bin/codesign', '-dvvv', client).stderr, re.M)[1]
    overlay = folder / 'overlay.json'
    overlay.write_text(json.dumps({'Replace': {str(ROOT / 'native_dns_fixture_darwin_test.go'):
                                                str(HERE / 'native_dns_test.go.fixture')}}))
    worker = folder / 'worker'
    run('go', 'test', '-c', '-overlay', overlay, '-o', worker, '.', cwd=ROOT)
    return service, client, worker, f'identifier "{identifier}" and cdhash H"{digest}"'


def sockets(stack):
    for _ in range(50):
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            udp.bind(('127.0.0.1', 0))
            tcp.bind(udp.getsockname())
            tcp.listen()
        except OSError:
            udp.close()
            tcp.close()
            continue
        return stack.enter_context(udp), stack.enter_context(tcp)
    raise RuntimeError('Cannot allocate an exclusive loopback UDP/TCP pair')


def resolver_status(name, port):
    blocks = re.split(r'(?m)^resolver #\d+\s*$', run('/usr/sbin/scutil', '--dns').stdout)
    for block in blocks:
        if re.search(r'(?m)^\s*domain\s*:\s*' + re.escape(name) + r'\s*$', block):
            port_ok = re.search(r'(?m)^\s*port\s*:\s*' + str(port) + r'\s*$', block)
            loopback = re.search(r'(?m)^\s*nameserver\[0\]\s*:\s*127\.0\.0\.1\s*$', block)
            return 'active' if port_ok and loopback else 'unexpected address or port'
    return 'absent'


def until(probe, expected, description, seconds=15):
    deadline = time.monotonic() + seconds
    while True:
        actual = probe()
        if actual == expected:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f'{description}: expected {expected}, observed {actual}')
        time.sleep(0.2)


def getaddrinfo(name):
    # Fresh process for each query avoids application caches and bounds a stalled DNS lookup.
    script = """import socket, sys
try:
    rows = socket.getaddrinfo(sys.argv[1], 443, socket.AF_INET, socket.SOCK_STREAM)
    print('matched' if any(r[4][0] == sys.argv[2] for r in rows) else 'other')
except socket.gaierror as error:
    print('absent' if error.errno in (socket.EAI_NONAME, socket.EAI_NODATA) else 'temporary lookup failure')
"""
    try:
        result = subprocess.run([sys.executable, '-c', script, name + '.', ANSWER], text=True,
                                capture_output=True, check=True, timeout=4)
    except subprocess.TimeoutExpired:
        return 'timeout'
    return result.stdout.strip()


def line(child, expected):
    if not select.select([child.stdout], [], [], 10)[0]:
        raise AssertionError('Fixture client timed out before ' + expected)
    actual = child.stdout.readline().strip()
    if actual != expected:
        raise AssertionError(f'Fixture client expected {expected}, got {actual!r}, exit={child.poll()}')


def terminate(child):
    if child.poll() is None:
        child.kill()
    child.wait(timeout=5)
    if child.stdin is not None:
        child.stdin.close()
    if child.stdout is not None:
        child.stdout.close()


def exercise(client, worker, name, crash):
    with ExitStack() as stack:
        udp, tcp = sockets(stack)
        port = udp.getsockname()[1]
        answering = subprocess.Popen([worker, '-test.run=^TestNativeDNSFixture$'], stdin=udp, stdout=tcp,
                                     env={**os.environ, 'GUARD_NATIVE_DNS_TEST_NAME': name})
        stack.callback(terminate, answering)
        child = subprocess.Popen([client, name, str(udp.fileno()), str(tcp.fileno())],
                                 pass_fds=(udp.fileno(), tcp.fileno()), stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, text=True)
        stack.callback(terminate, child)
        line(child, 'published')
        child.stdin.write('renew\n')
        child.stdin.flush()
        line(child, 'renewed')
        until(lambda: resolver_status(name, port), 'active',
              'configd accepted the DNS subkey and renewal read it back, but scutil --dns did not adopt it')
        until(lambda: getaddrinfo(name), 'matched', 'getaddrinfo via the scoped resolver')
        if crash:
            child.kill()
            child.wait(timeout=5)
        else:
            child.stdin.write('clear\n')
            child.stdin.flush()
            line(child, 'cleared')
        until(lambda: resolver_status(name, port), 'absent', 'resolver withdrawal')
        # Leave both answering sockets up. A stale route would still return ANSWER.
        until(lambda: getaddrinfo(name) in ('other', 'absent'), True, 'getaddrinfo after withdrawal', seconds=30)
        if answering.poll() is not None:
            raise AssertionError('Production DNS responder exited during the test')
        print('Passed scutil + getaddrinfo publication and', 'client SIGKILL' if crash else 'explicit withdrawal')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compile-only', action='store_true')
    args = parser.parse_args()
    if sys.platform != 'darwin' or os.getuid() == 0:
        sys.exit('Requires an ordinary macOS account')
    token = uuid.uuid4().hex
    label = 'local.aiexitguard.dnsfixture.' + token
    names = [f'lease-{phase}-{token}.test' for phase in ('clear', 'crash')]
    with tempfile.TemporaryDirectory() as work, ExitStack() as stack:
        folder = Path(work)
        service, client, worker, requirement = build(folder, label, names)
        if args.compile_only:
            print('Compiled and signed the isolated native DNS fixture')
            return
        sudo = ['/usr/bin/sudo', '-n']
        # Limit the elevated surface to the randomly named root-owned fixture directory and job.
        dest = Path(run(*sudo, '/usr/bin/mktemp', '-d', '/private/var/tmp/aiexitguard-dns.XXXXXXXX').stdout.strip())
        stack.callback(run, *sudo, '/bin/rmdir', dest)
        program = dest / 'helper'
        target_plist = dest / 'service.plist'
        local_plist = folder / 'service.plist'
        local_plist.write_bytes(plistlib.dumps({'Label': label, 'ProgramArguments': [str(program), requirement],
                                                'MachServices': {label: True}}))
        for src, dst, mode in ((service, program, '0755'), (local_plist, target_plist, '0644')):
            run(*sudo, '/usr/bin/install', '-o', 'root', '-g', 'wheel', '-m', mode, src, dst)
            stack.callback(run, *sudo, '/bin/rm', '-f', dst)
        run(*sudo, '/bin/launchctl', 'bootstrap', 'system', target_plist)
        stack.callback(run, *sudo, '/bin/launchctl', 'bootout', 'system/' + label)
        for name, crash in zip(names, (False, True)):
            exercise(client, worker, name, crash)


if __name__ == '__main__':
    main()
