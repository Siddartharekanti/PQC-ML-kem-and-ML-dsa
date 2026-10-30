#!/bin/sh
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE"
if [ ! -x .venv/bin/python3 ]; then
  echo "Missing virtual environment. Run ./setup.sh first." >&2
  exit 1
fi
exec .venv/bin/python3 bob.py "$@"
