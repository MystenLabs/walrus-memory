#!/usr/bin/env bash
set -euo pipefail
export PATH="$HOME/.local/bin:/usr/local/bin:/opt/homebrew/bin:$PATH"
task_root="$(cd -- "$(dirname -- "$0")" && pwd -P)"
exec /usr/bin/python3 "$task_root/tools/renewal-testnet/orchestrate.py" "$@"
