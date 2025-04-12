#!/bin/bash

INSTALL_PATH="$1"
PYTHON_BIN="$2"

python -m venv "$INSTALL_PATH" || exit 1
"$INSTALL_PATH/bin/pip" install . || exit 1
