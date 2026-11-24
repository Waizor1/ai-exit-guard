#!/bin/zsh
set -eu
cd "${0:A:h}"
engine=/Applications/ProxyBridge.app/Contents/MacOS/ProxyBridge
if [[ ! -x "$engine" ]]; then
    echo 'Сначала установите ProxyBridge для macOS. Системное разрешение выдаётся при первом запуске.'
    open 'https://github.com/InterceptSuite/ProxyBridge/releases/tag/v4.1.3_Macos'
    exit 1
fi
agent="$HOME/Library/LaunchAgents/local.aiexitguard.filter.plist"
if [[ -f "$agent" ]]; then
    ./guard filter-off
    echo 'Автозапуск системного фильтра выключен.'
else
    ./guard filter-on
    echo 'Автозапуск фильтра включён. При первом запуске подтвердите системное разрешение. Окно можно закрыть.'
fi
