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
        assert first.startswith(b'CONNECT api.openai.com:443 ')
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
    helper.write_text('#!/bin/sh\ncd "$(dirname "$0")" || exit 1\ncase "$1" in\nproxy-serve) exec ./relay "$@" ;;\nproxy-monitor) cat >/dev/null; exec cat fixture ;;\n*) exit 1 ;;\nesac\n')
    helper.chmod(0o755)
    entry=(root/'main.swift').read_text().split('let app=NSApplication.shared')[0]
    entry=entry.replace('            proxy.applyTunnelRoute()','            // Isolated test: keep system network preferences untouched.')
    (folder/'main.swift').write_text(entry+'''
let app=NSApplication.shared
let m=Monitor()
m.online=true
m.policyDate={RegionPolicy.reviewed.addingTimeInterval(10)}
m.history=ExitHistory(store:UserDefaults(suiteName:UUID().uuidString)!)
m.proxy.expected="1.1.1.1"
let data=Data(CommandLine.arguments[1].utf8)
try m.proxy.relay(data)
m.proxy.ready=true
print("START"); fflush(stdout)
while let instruction=readLine(),instruction != "quit" {
    m.check()
    let end=Date().addingTimeInterval(5)
    while m.running && Date()<end { RunLoop.main.run(until:Date().addingTimeInterval(0.01)) }
    precondition(!m.running)
    print(m.overall == .avoid ? "RED" : (m.proxy.allowedUntil > 0 ? "OPEN" : "CLOSED")); fflush(stdout)
}
m.proxy.shutdown()
''')
    subprocess.run(['xcrun','swiftc',folder/'main.swift',*(p for p in root.glob('*.swift') if p.name!='main.swift'),'-o',exe],check=True)
    spec=json.dumps(dict(Scheme='http',Host='127.0.0.1',Port=origin.server_address[1],User='',Password=''))
    proc=subprocess.Popen([exe,spec],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
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
    def connect():
        conn=socket.create_connection(('127.0.0.1',port),timeout=2)
        conn.sendall(b'CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\n\r\n')
        resp=http.client.HTTPResponse(conn);resp.begin()
        return conn,resp.status
    def denied():
        conn,status=connect();conn.close()
        assert status==503,status
    try:
        assert proc.stdout.readline().strip()=='START'
        denied()
        for mode in ('red','changed'):
            assert cycle('green')=='OPEN'
            conn,status=connect()
            assert status==200
            conn.sendall(b'before\n')
            assert conn.recv(128)==b'received\n'
            assert cycle(mode)=='RED'
            count=origin.connections
            try: conn.sendall(b'after\n');assert conn.recv(128)==b''
            except (ConnectionResetError,BrokenPipeError): pass
            finally: conn.close()
            for _ in range(6): denied()
            assert origin.connections==count
            assert b'after\n' not in origin.payloads
            assert cycle('partial')=='CLOSED'
            denied()
        assert cycle('green')=='OPEN'
        conn,status=connect();assert status==200
        assert cycle('stale-soon')=='OPEN'
        time.sleep(3.2)
        denied()
        assert conn.recv(32)==b''
        conn.close()
        assert cycle('green')=='OPEN'
        print('PASS: starts closed; high risk and changed exit each disconnect a live tunnel, reject six new ones, deliver zero subsequent payloads, and recover on green.')
    finally:
        proc.stdin.write('quit\n');proc.stdin.flush();proc.wait(5)
        origin.shutdown()
