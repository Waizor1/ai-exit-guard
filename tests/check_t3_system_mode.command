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

# Exercise only name resolution for the live providers; never stop a live route.
import socket
import urllib.parse
expected_ingress = "127.0.0.2"
for host in ("api.anthropic.com","api.openai.com","daily-cloudcode-pa.googleapis.com"):
    addresses={i[4][0] for i in socket.getaddrinfo(host,443,type=socket.SOCK_STREAM)}
    if not addresses or addresses != {expected_ingress}:
        sys.exit("Маршрут через системный DNS не подтверждён для "+host)
runtime = pathlib.Path.home()/".t3/userdata/server-runtime.json"
origin = urllib.parse.urlsplit(json.loads(runtime.read_bytes())["origin"])
if origin.scheme!="http" or origin.hostname!="127.0.0.1" or not origin.port:
    sys.exit("Не удалось подтвердить локальный мост T3.")
try:
    with socket.create_connection((origin.hostname, origin.port),timeout=3):
        pass
except OSError:
    sys.exit("Локальный порт T3 недоступен в этой среде.")
with tempfile.TemporaryDirectory() as local:
    with socket.socket(socket.AF_UNIX) as listener, socket.socket(socket.AF_UNIX) as client:
        address=str(pathlib.Path(local)/"sock")
        listener.bind(address);listener.listen(1);client.settimeout(2);client.connect(address)
        connection,_=listener.accept()
        connection.close()
print("Системный DNS трёх сервисов, локальный порт T3 и Unix-сокет проверены.",flush=True)

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
        parent_ok = result["Direct"]
        child_ok = result["Child"]
        print(f"{name}: обычный HTTPS самого процесса {'доступен' if parent_ok else 'недоступен'}; "
              f"GitHub у дочернего curl {'доступен' if child_ok else 'недоступен'}.", flush=True)
        passed &= parent_ok and child_ok
        if alias:
            passed &= result["SSH"]
            print("  SSH к выбранному серверу: " + ("доступен" if result["SSH"] else "проверка не прошла"), flush=True)

    # These repository checks use disposable listeners with a counting upstream.
    # They never rotate a production IP or change a live lease.
    tests = [
        [go,"test","-count=1","-run","^(TestServiceTunnelsAndLeases|TestIngressUsesOnlyGuard|TestProfileOnlyMatchesServiceDomains)$","."],
        ["python3","tests/check_red_relay.py"],
    ]
    for cmd in tests:
        completed = subprocess.run(cmd, timeout=240, env={**os.environ, "PATH": str(pathlib.Path(go).parent) + os.pathsep + os.environ.get("PATH","")})
        passed &= completed.returncode == 0

    if not passed:
        sys.exit("Проверка системного режима не пройдена. Настройки T3 сохранены.")
    print("Проверки тестовых процессов и тестового красного маршрута пройдены. Для переключения ещё требуется проверка настоящих клиентов T3.")
PY
