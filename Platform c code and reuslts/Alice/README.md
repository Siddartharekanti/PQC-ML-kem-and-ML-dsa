# Computer 1 — Alice

This folder is a complete Alice client matching the QSC/1 Bob server in the parent project. It supports mutually authenticated ML-KEM-768 + ML-DSA-65 handshakes and two-way AES-256-GCM protected text/file communication.

## Setup

The included `bob.pub.json` is Bob's pinned public identity. Alice's generated private identity must remain only on Alice's computer; copy only `alice.pub.json` to Bob.

```bash
chmod +x setup.sh run_client.sh
./setup.sh
```

## Connect to Bob

Start Bob first:

```bash
../run_server.sh --listen 0.0.0.0 --port 5002
```

Then connect Alice using Bob's IP address:

```bash
./run_client.sh BOB_IP --port 5002
```

For both programs on the same computer:

```bash
./run_client.sh 127.0.0.1 --port 5002
```

Alice and Bob both remain able to receive while you type and send. Commands are:

```text
Hello Bob                         send text
/send "path/to/a file.bin"       send a file
/payload payload_1KB.bin          send the official 1 KB payload
/payload payload_100KB.bin        send the official 100 KB payload
/payload payload_10MB.bin         send the official 10 MB payload
/help                             show commands
/quit                             close securely
```

Files received from Bob are saved without overwriting existing files under `received/`. SHA-256 receipts verify the exact bytes transferred.

## Batch/demo commands

```bash
./run_client.sh BOB_IP --message "Hello Bob"
./run_client.sh BOB_IP --send payload_1KB.bin
./run_client.sh BOB_IP --demo
```

Use `--help` for all options. `qsc_core.py` is the shared wire-compatible protocol implementation and `cryptography==50.0.2` is pinned in `requirements.txt`.

## Run N verified sessions and recover from attacks

Start Bob:

```bash
../run_server.sh --listen 0.0.0.0 --port 5002 --runs 10 \
  --attack-csv results/bob_attack_events.csv
```

Then start Alice:

```bash
./run_client.sh 10.12.138.147 --port 5002 --runs 10 \
  --attack-csv results/alice_attack_events.csv
```

Use `--runs N` on both Alice and Bob. Mixing `--runs` with `--demo` or normal
chat is a mode mismatch, not an attack; authenticated text is safely ignored by
the automated payload receiver.

For every successful run, all three official payloads travel in both
directions and are checked by SHA-256. An interrupted or attacked session does
not increment the success counter: its details are appended to the selected
CSV, the connection is discarded, and Alice reconnects while Bob waits for the
fresh session.
