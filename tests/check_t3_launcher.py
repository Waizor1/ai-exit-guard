"""Check the installed launcher logic with a disposable T3 runtime and no real clients."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as base:
    stage = Path(base)
    record = stage / ".t3/userdata/server-runtime.json"
    record.parent.mkdir(parents=True)
    # Inspect argv passed to Seatbelt. This fixture does not open a connection.
    launcher = (root / "packaging/guarded-client").read_text()
    assert launcher.count("exec /usr/bin/sandbox-exec ") == 1
    for binary in ("guarded-codex", "guarded-claude", "agy"):
        target = stage / binary
        target.write_text(launcher.replace("exec /usr/bin/sandbox-exec ", 'exec "$HOME/record-policy" '))
        target.chmod(0o755)
    for tool in ("codex", "claude", "guard", "record-policy"):
        script = stage / tool
        script.write_text("#!/bin/sh\n" + {
            "guard": 'echo "$HOME/codex"',
            "record-policy": 'echo "$2"; echo "${NO_PROXY:-empty}"'
        }.get(tool, "exit 0") + "\n")
        script.chmod(0o755)
    for origin, endpoint, allowed in (
        ("http://127.0.0.1:3773", "http://127.0.0.1:3773/mcp", True),
        ("http://127.0.0.1:3774", "http://127.0.0.1:3773/mcp", False),
        ("http://127.0.0.1:22", "http://127.0.0.1:22/mcp", False),
        ("http://outside.test:3773", "http://outside.test:3773/mcp", False)
    ):
        record.write_text(json.dumps({"origin": origin}))
        for name in ("guarded-codex", "guarded-claude", "agy"):
            result = subprocess.check_output([str(stage / name)], text=True, env={
                **os.environ, "HOME": base, "PATH": base + ":" + os.environ["PATH"],
                "T3_ACP_MCP_ENDPOINT": endpoint, "NO_PROXY": "*"
            }).splitlines()
            policy, bypass = result
            assert "(deny network-outbound)" in policy and 'tcp "localhost:39178"' in policy
            assert policy.count("(allow network-outbound") == (2 if allowed else 1)
            assert ('tcp "localhost:3773"' in policy) == allowed
            assert bypass == ("127.0.0.1" if allowed else "empty")
print("PASS: all three launchers scope MCP to the registered local TCP port")
