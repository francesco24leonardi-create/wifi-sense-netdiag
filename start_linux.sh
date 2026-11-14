#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
if [[ ! -x .venv/bin/python ]]; then
  python3 -m venv --system-site-packages .venv
  .venv/bin/python -m pip install -r requirements.txt
fi
export PYWEBVIEW_GUI="${PYWEBVIEW_GUI:-gtk}"
exec .venv/bin/python main.py "$@"
