#!/bin/zsh -l
export PATH="$PATH:$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin"
export HTTPS_PROXY=http://127.0.0.1:39178 HTTP_PROXY=http://127.0.0.1:39178
export https_proxy="$HTTPS_PROXY" http_proxy="$HTTP_PROXY"
unset ALL_PROXY all_proxy NO_PROXY no_proxy
cd "$HOME" || exit 1
exec codex "$@"
