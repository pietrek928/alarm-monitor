#!/bin/bash

INSTALL_PATH="$1"
PYTHON_BIN="${2:-python3}"

args=(sync)
if [ -n "$2" ]; then
  args+=(--python "$PYTHON_BIN")
fi
UV_PROJECT_ENVIRONMENT="$INSTALL_PATH" "$PYTHON_BIN" -m uv "${args[@]}"
