#!/bin/zsh -l
set -eu
launcher="${0:A:h}/guarded-claude"
cd "$HOME"
exec "$launcher" "$@"
