#!/bin/sh
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE"
python3 -m venv .venv
.venv/bin/python3 -m pip install -r requirements.txt
if [ ! -f alice.key.json ]; then
  .venv/bin/python3 alice.py --init
fi
echo "Alice setup complete. Copy alice.pub.json to Bob, then run: ./run_client.sh BOB_IP"
