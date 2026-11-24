"""Check legacy Guard shortcuts hand the native client its normal arguments and network."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as tmp:
    base = Path(tmp)
    for name in ("guard","codex","claude"):
        binary = base / name
        script = 'echo "$HOME/codex"' if name == "guard" else 'printf "%s\\n" "$1" "${HTTP_PROXY-unset}" "$HTTPS_PROXY" "$NO_PROXY"'
        binary.write_text("#!/bin/sh\n" + script + "\n")
        binary.chmod(0o755)
    for name in ("guarded-codex", "guarded-claude", "agy"):
        launch = base / name
        shutil.copy2(root/"packaging/guarded-client",launch)
        env = dict(os.environ, HOME=tmp, PATH=tmp+":"+os.environ["PATH"],
                   HTTP_PROXY="http://127.0.0.1:39178", HTTPS_PROXY="http://office.example:8000",
                   NO_PROXY="localhost,.office.example")
        result = subprocess.check_output([str(launch),"arg with spaces"],env=env,text=True)
        assert result.splitlines() == ["arg with spaces","unset",env["HTTPS_PROXY"],env["NO_PROXY"]], name
print("PASS: three provider launchers preserve developer network settings and arguments")
