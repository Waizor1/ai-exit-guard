"""Run the macOS worker with real inherited sockets and only private MCP fixtures."""
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]

with tempfile.TemporaryDirectory() as temporary:
    home = Path(temporary)
    binary = home / "guard"
    subprocess.run(["go", "build", "-o", binary, "."], cwd=ROOT,
                   env={**os.environ, "CGO_ENABLED": "0"}, check=True)
    (home/".claude.json").write_text(json.dumps({"mcpServers": {
        "local": {"url": "https://localhost:3773/mcp"},
        "intranet": {"url": "https://private.example.test/mcp/SECRET-CANARY"}
    }}))
    with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp:
        tcp.bind(("127.0.0.1", 0))
        tcp.listen()
        udp.bind(tcp.getsockname())
        env = {"HOME": str(home), "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "GODEBUG": "netdns=cgo"}
        with subprocess.Popen([binary, "mcp-dns"], env=env, stdin=udp, stdout=tcp,
                              stderr=subprocess.PIPE) as worker:
            try:
                assert select.select([worker.stderr], [], [], 8)[0], "missing worker status"
                assert worker.stderr.readline() == b"[]\n", "private host entered DNS lease"
                assert worker.poll() is None
            finally:
                worker.terminate()
                worker.wait(timeout=5)
print("PASS: production worker kept private endpoints out of leases and stopped on request.")
