#!/bin/zsh
# Disposable Mac check. Does not modify Guard, T3, hosts or ProxyBridge.
set -eu
cd "${0:A:h}/.."
python3 - "$@" <<'PY'
import json
import os
import pathlib
import shutil
import re
import subprocess
import sys
import tempfile

if sys.platform != "darwin":
    sys.exit("Эта проверка предназначена для macOS.")

go = shutil.which("go") or next((str(p) for p in (pathlib.Path("/opt/homebrew/bin/go"), pathlib.Path("/usr/local/go/bin/go")) if p.is_file()), None)
if not go:
    sys.exit("Для тестовой сборки требуется Go.")
alias = ""
if sys.argv[1:]:
    if len(sys.argv) != 3 or sys.argv[1] != "--ssh" or not re.fullmatch("[A-Za-z0-9][A-Za-z0-9_.-]{0,90}", sys.argv[2]):
        sys.exit("Необязательный параметр: --ssh имя_из_конфига_SSH")
    alias = sys.argv[2]

with tempfile.TemporaryDirectory(prefix="guard-t3-check-") as tmp:
    base = pathlib.Path(tmp)
    neutral = base / "network-control"
    subprocess.run([go, "build", "-o", str(neutral), "./tests/testdata/t3-network"], check=True)

    def run_probe(binary):
        return json.loads(subprocess.check_output([str(binary), alias], timeout=35))

    print("Проверка доступа к GitHub. Аккаунты ИИ не используются.", flush=True)
    control = run_probe(neutral)
    if not (control["Direct"] and control["Child"]):
        sys.exit("НЕТ РЕЗУЛЬТАТА: обычный процесс или его curl не достиг GitHub. Сравнивать режимы в этой среде нельзя.")

    passed = True
    for name in ("claude", "codex", "antigravity"):
        probe = base / name
        shutil.copy2(neutral, probe)
        result = run_probe(probe)
        isolated = not result["Direct"]
        child_ok = result["Child"]
        print(f"{name}: обычный HTTPS самого процесса {'ограничен' if isolated else 'доступен'}; "
              f"GitHub у дочернего curl {'доступен' if child_ok else 'недоступен'}.", flush=True)
        passed &= isolated and child_ok
        if alias:
            passed &= result["SSH"]
            print("  SSH к выбранному серверу: " + ("доступен" if result["SSH"] else "проверка не прошла"), flush=True)

    # These repository checks use disposable listeners with a counting upstream.
    # They never rotate a production IP or change a live lease.
    tests = [
        [go,"test","-count=1","-run","^(TestServiceTunnelsAndLeases|TestIngressUsesOnlyGuard|TestMCPRoutes)$","."],
        ["python3","tests/check_red_relay.py"],
    ]
    for cmd in tests:
        completed = subprocess.run(cmd, timeout=240, env={**os.environ, "PATH": str(pathlib.Path(go).parent) + os.pathsep + os.environ.get("PATH","")})
        passed &= completed.returncode == 0

    if not passed:
        sys.exit("Проверка системного режима не пройдена. Настройки T3 сохранены.")
    print("Проверки тестовых процессов и тестового красного маршрута пройдены. Для переключения ещё требуется проверка настоящих клиентов T3.")
PY
