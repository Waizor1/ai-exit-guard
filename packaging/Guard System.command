#!/bin/zsh
set -eu
cd "${0:A:h}"
engine=/Applications/ProxyBridge.app/Contents/MacOS/ProxyBridge
if [[ ! -x "$engine" ]]; then
    echo 'Сначала установите ProxyBridge для macOS. Системное разрешение выдаётся при первом запуске.'
    open 'https://github.com/InterceptSuite/ProxyBridge/releases/tag/v4.1.3_Macos'
    exit 1
fi
echo 'Guard направит известные ИИ-домены через ваш прокси. Для защищённых клиентов действует отдельное правило. Оставьте это окно открытым. Ctrl+C отключает системные правила.'
set -o pipefail
./guard system-profile | "$engine" --profile - --verbose 1
