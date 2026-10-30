#!/bin/sh
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE"
python3 -m venv .venv
.venv/bin/python3 -m pip install -r requirements.txt
echo "Bob setup complete. Run: ./run_server.sh"
