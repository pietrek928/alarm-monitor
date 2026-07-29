#!/bin/bash
set -euo pipefail

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${1:-python3}"

if [[ ! -f "$INSTALL_DIR/pyvenv.cfg" ]]; then
  "$PYTHON_BIN" -m venv "$INSTALL_DIR"
fi

"$INSTALL_DIR/bin/python" -m pip install -U uv
UV_PROJECT_ENVIRONMENT="$INSTALL_DIR" \
  "$INSTALL_DIR/bin/python" -m uv sync \
  --no-editable \
  --python "$INSTALL_DIR/bin/python" \
  --cache-dir=/tmp/uv-cache
