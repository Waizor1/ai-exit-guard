"""Connect the real Swift verdict and relay controller to a Go relay and a counting upstream.
Only the diagnostic responses, Happ configuration hook and local listener address are substituted.
"""
import datetime
import http.client
import json
import os
import pathlib
import plistlib
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time

root = pathlib.Path(__file__).resolve().parents[1]

class Origin(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(10)
        first = self.rfile.readline()
        while self.rfile.readline() not in (b'\r\n', b''):
            pass
        assert first.split()[1] in (b'api.openai.com:443', b'daily-cloudcode-pa.googleapis.com:443')
        self.server.connections += 1
        self.wfile.write(b'HTTP/1.1 200 OK\r\n\r\n')
        for data in self.rfile:
            self.server.payloads.append(data)
            self.wfile.write(b'received\n')

def reading(host, mode):
    ip = '1.1.1.1'
    return dict(Host=host,IP='8.8.8.8' if mode=='changed' else ip,AssessmentIP=ip,
                Status='green',Detail='',RiskDetail='',Risk=99 if mode=='red' else 2,
                Trust=95,Country='DE',Network='Fixture',InfoDetail='',TraceCountry='DE',InfoChecked=True,
                Checked=datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))

with tempfile.TemporaryDirectory() as temp, socketserver.ThreadingTCPServer(('127.0.0.1',0),Origin) as origin:
    origin.connections=0
    origin.payloads=[]
    threading.Thread(target=origin.serve_forever,daemon=True).start()
    with socket.socket() as reserved:
        reserved.bind(('127.0.0.1',0))
        port=reserved.getsockname()[1]
    folder=pathlib.Path(temp)
    bundle=folder/'GateFixture.app/Contents'
    res=bundle/'Resources'
    exe=bundle/'MacOS/Runner'
    res.mkdir(parents=True)
    exe.parent.mkdir()
    (bundle/'Info.plist').write_bytes(plistlib.dumps(dict(CFBundleIdentifier='local.aiexitguard.relayfixture',
        CFBundleExecutable='Runner',CFBundlePackageType='APPL')))
    subprocess.run(['go','build','-ldflags',f'-X main.localProxy=127.0.0.1:{port}','-o',res/'relay','.'],cwd=root,check=True)
    helper=res/'guard'
    helper.write_text('#!/bin/sh\ncd "$(dirname "$0")" || exit 1\ncase "$1" in\nproxy-serve) exec ./relay "$@" ;;\nproxy-monitor) cat >/dev/null; exec cat fixture ;;\nproxy-check) cat >/dev/null; echo 1.1.1.1 ;;\nproxy-profile-check) cat >/dev/null; echo \'{"IP":"1.1.1.1","Country":"DE","Status":"ok"}\' ;;\n*) exit 1 ;;\nesac\n')
    helper.chmod(0o755)
    entry=(root/'main.swift').read_text().split('let app=NSApplication.shared')[0]
    entry=entry.replace('            proxy.applyTunnelRoute()','            // Isolated test: keep system network preferences untouched.')
    (folder/'main.swift').write_text(entry+'''
let app=NSApplication.shared
// Model an already connected app consistently in each independent runner:
// the persisted pin and in-memory Keychain entry refer to the same route.
precondition(Bundle.main.bundleIdentifier=="local.aiexitguard.relayfixture")
UserDefaults.standard.set(false,forKey:"proxyOnly")
UserDefaults.standard.set(false,forKey:"proxyPaused")
UserDefaults.standard.set("1.1.1.1",forKey:"proxyExpected")
let data=Data(CommandLine.arguments[1].utf8)
try ProxyVault.save(data)
let m=Monitor()
m.online=true
m.policyDate={RegionPolicy.reviewed.addingTimeInterval(10)}
m.history=ExitHistory(store:UserDefaults(suiteName:UUID().uuidString)!)
try m.proxy.relay(data)
m.proxy.ready=true
print("START"); fflush(stdout)
while let instruction=readLine(),instruction != "quit" {
    if instruction == "advisory" || instruction == "guarded" {
        m.setProxyOnly(instruction == "advisory")
        print(m.proxy.proxyOnly ? "ADVISORY" : "GUARDED");fflush(stdout);continue
    }
    if instruction == "pause" || instruction == "resume" {
        m.proxy.profileChanged={ _ in m.invalidate("",closeAll:false);m.check() }
        m.proxy.routeChanged={ m.invalidate("") }
        let pause=instruction=="pause"
        m.proxy.setCommonPaused(pause)
        let limit=Date().addingTimeInterval(4)
        while m.proxy.busy && Date()<limit {RunLoop.main.run(until:Date().addingTimeInterval(0.01))}
        precondition((m.proxy.plan?.CommonPaused == true)==pause)
        print("APPLIED");fflush(stdout);continue
    }
    if instruction == "individual" || instruction == "common" {
        if instruction == "individual" {
            m.proxy.useIndividual("Antigravity",line:"http://127.0.0.1:12345",scheme:"http")
            let limit=Date().addingTimeInterval(4)
            while m.proxy.busy && Date()<limit {RunLoop.main.run(until:Date().addingTimeInterval(0.01))}
        } else {m.proxy.useCommon("Antigravity")}
        guard let raw=ProxyVault.read() else {fatalError("Fixture profile missing after "+instruction)}
        let saved=try ProxyPlan.load(raw)
        precondition(saved.Profiles.keys.sorted()==(instruction=="individual" ? ["Antigravity"]:[]))
        print("APPLIED");fflush(stdout);continue
    }
    m.check()
    let end=Date().addingTimeInterval(5)
    while m.running && Date()<end { RunLoop.main.run(until:Date().addingTimeInterval(0.01)) }
    precondition(!m.running)
    print(m.overall == .avoid ? "RED" : (m.proxy.allowedUntil > 0 ? "OPEN" : "CLOSED")); fflush(stdout)
}
m.proxy.shutdown()
''')
    # Store profiles in memory so exercising the actual Apply buttons' actions cannot
    # write credentials to the user's Keychain.
    proxy_source=(root/'ProxyClient.swift').read_text()
    start=proxy_source.index('enum ProxyVault {');end=proxy_source.index('final class ProxyClient:',start)
    proxy_source=proxy_source[:start]+"""enum ProxyVault {
        static var data:Data?
        static func save(_ value:Data)throws {data=value}
        static func read()->Data? {data}
        static func readForUpdate()throws -> Data? {data}
        static func clear(){data=nil}
    }
"""+proxy_source[end:]
    (folder/'ProxyClient.swift').write_text(proxy_source)
    subprocess.run(['xcrun','swiftc',folder/'main.swift',folder/'ProxyClient.swift',*(p for p in root.glob('*.swift') if p.name not in ('main.swift','ProxyClient.swift')),'-o',exe],check=True)
    spec=json.dumps(dict(Scheme='http',Host='127.0.0.1',Port=origin.server_address[1],User='',Password=''))
    proc=subprocess.Popen([exe,spec],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
    def stop_fixture(proc):
        try:
            proc.stdin.close()  # EOF is also a normal controller shutdown.
        except BrokenPipeError:
            pass
        status=proc.wait(5)
        if status and sys.exc_info()[0] is None:
            raise RuntimeError(f'fixture exited with status {status}')
    def cycle(mode):
        hosts=['claude.ai','api.anthropic.com','chatgpt.com','api.openai.com']
        (res/'fixture').write_text(''.join(json.dumps(reading(h,mode if i==3 else 'green'))+'\n' for i,h in enumerate(hosts)))
        if mode=='partial':
            (res/'fixture').write_text((res/'fixture').read_text().splitlines()[0]+'\n')
        elif mode=='stale-soon':
            old=(datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(seconds=177)).strftime('%Y-%m-%dT%H:%M:%SZ')
            records=[dict(json.loads(line),Checked=old) for line in (res/'fixture').read_text().splitlines()]
            (res/'fixture').write_text(''.join(json.dumps(row)+'\n' for row in records))
        proc.stdin.write('check\n');proc.stdin.flush()
        return proc.stdout.readline().strip()
    def connect(host='api.openai.com'):
        conn=socket.create_connection(('127.0.0.1',port),timeout=2)
        conn.sendall(f'CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n'.encode())
        resp=http.client.HTTPResponse(conn);resp.begin()
        return conn,resp.status
    def denied(host='api.openai.com', settle=0.0):
        deadline=time.monotonic()+settle
        while True:
            conn,status=connect(host);conn.close()
            if status==503 or time.monotonic()>=deadline:
                assert status==503,status
                return
            time.sleep(0.05)
    try:
        assert proc.stdout.readline().strip()=='START'
        denied()
        for mode,host in [('red','daily-cloudcode-pa.googleapis.com'),('changed','api.openai.com')]:
            assert cycle('green')=='OPEN'
            conn,status=connect(host)
            assert status==200
            conn.sendall(b'before\n')
            assert conn.recv(128)==b'received\n'
            assert cycle(mode)=='RED'
            count=origin.connections
            try: conn.sendall(b'after\n');assert conn.recv(128)==b''
            except (ConnectionResetError,BrokenPipeError): pass
            finally: conn.close()
            for _ in range(6): denied(host)
            assert origin.connections==count
            assert b'after\n' not in origin.payloads
            assert cycle('partial')=='CLOSED'
            denied()
        assert cycle('green')=='OPEN'
        conn,status=connect();assert status==200
        assert cycle('stale-soon')=='OPEN'
        assert cycle('partial')=='OPEN'
        conn.sendall(b'during-recheck\n');assert conn.recv(128)==b'received\n'
        time.sleep(3.2)
        denied()
        assert conn.recv(32)==b''
        conn.close()
        assert cycle('green')=='OPEN'
        print('PASS: starts closed; high risk and changed exit each disconnect a live tunnel, reject six new ones, deliver zero subsequent payloads, and recover on green.')
    finally:
        stop_fixture(proc)
    plan=dict(Common=json.loads(spec),Profiles={})
    proc=subprocess.Popen([exe,json.dumps(plan)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
    def regional_check(country):
        hosts=['claude.ai','api.anthropic.com','chatgpt.com','api.openai.com']
        rows=[reading(h,'green') for h in hosts]
        rows.append(dict(reading('accounts.google.com','green'),Status='google',TraceCountry=country,Trust=None))
        (res/'fixture').write_text(''.join(json.dumps(row)+'\n' for row in rows))
        proc.stdin.write('check\n');proc.stdin.flush();return proc.stdout.readline().strip()
    try:
        assert proc.stdout.readline().strip()=='START'
        denied('daily-cloudcode-pa.googleapis.com')
        assert regional_check('DE')=='OPEN'
        chat,status=connect();assert status==200
        google,status=connect('daily-cloudcode-pa.googleapis.com');assert status==200
        def set_mode(mode):
            proc.stdin.write(mode+'\n');proc.stdin.flush()
            assert proc.stdout.readline().strip()==mode.upper()
        set_mode('advisory')
        assert regional_check('RU')=='RED'
        google.sendall(b'advisory\n');assert google.recv(128)==b'received\n'
        set_mode('guarded')
        assert google.recv(16)==b''
        denied('daily-cloudcode-pa.googleapis.com')
        chat.sendall(b'approved-handoff\n');assert chat.recv(128)==b'received\n'
        assert regional_check('DE')=='OPEN'
        google.close()
        google,status=connect('daily-cloudcode-pa.googleapis.com');assert status==200
        set_mode('advisory')
        set_mode('guarded')  # no fresh assessment in this generation
        assert google.recv(16)==b'' and chat.recv(16)==b''
        denied();denied('daily-cloudcode-pa.googleapis.com')
        google.close();chat.close()
        assert regional_check('DE')=='OPEN'
        google,status=connect('daily-cloudcode-pa.googleapis.com');assert status==200
        chat,status=connect();assert status==200
        print('PASS: enabling IP protection preserves a confirmed live OpenAI tunnel, closes red Google, and fails closed on unverified routes.')
        assert regional_check('RU')=='RED'
        assert google.recv(16)==b''
        denied('daily-cloudcode-pa.googleapis.com')
        chat.sendall(b'still-open\n');assert chat.recv(128)==b'received\n'
        assert regional_check('DE')=='OPEN'
        google.close()
        for mode in ('individual','common'):
            proc.stdin.write(mode+'\n');proc.stdin.flush();assert proc.stdout.readline().strip()=='APPLIED'
            denied('daily-cloudcode-pa.googleapis.com')
            chat.sendall(b'unchanged\n');assert chat.recv(128)==b'received\n'
        chat.close()
        print('PASS: Google RU closes live and new Google tunnels, OpenAI stream continues, DE restores access.')
    finally:
        stop_fixture(proc)
    plan['Profiles']={'Antigravity':dict(Endpoint=json.loads(spec),Expected='1.1.1.1')}
    proc=subprocess.Popen([exe,json.dumps(plan)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
    try:
        assert proc.stdout.readline().strip()=='START'
        assert regional_check('DE')=='OPEN'
        chat,status=connect();assert status==200
        google,status=connect('daily-cloudcode-pa.googleapis.com');assert status==200
        for action in ('pause','resume'):
            proc.stdin.write(action+'\n');proc.stdin.flush();assert proc.stdout.readline().strip()=='APPLIED'
            if action=='pause':
                assert chat.recv(16)==b''
                chat.close()
                denied()
            else:
                denied(settle=2.0)
            google.sendall(b'separate-google\n');assert google.recv(128)==b'received\n'
        assert regional_check('DE')=='OPEN'
        chat,status=connect();assert status==200
        chat.close();google.close()
        print('PASS: Mac common pause and resume preserve an individual Antigravity stream; OpenAI resumes only after a fresh lease.')
    finally:
        stop_fixture(proc)
        origin.shutdown()
