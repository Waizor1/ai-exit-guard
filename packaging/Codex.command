#!/bin/zsh -l
set -eu
launcher="${0:A:h}/guarded-codex"
cd "$HOME"
exec "$launcher" "$@"
