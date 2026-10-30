# Computer 2 — Bob

`bob.py` is the standalone server. No identity key is pre-generated. Generate Bob's identity once:

```bash
chmod +x setup.sh run_server.sh
./setup.sh
.venv/bin/python3 bob.py --init
```

Keep the generated `bob.key.json` private. Send only `bob.pub.json` to Alice. Place Alice's independently verified `alice.pub.json` here, then run:

```bash
./run_server.sh --listen 0.0.0.0 --port 5002
```

The default mode is two-way communication: Bob receives Alice's encrypted text/files while also allowing Bob to send text/files back:

```bash
./run_server.sh --listen 0.0.0.0 --port 5002
```

After Alice connects, type text to send it back to Alice. Bob also supports:

```text
/send "/path/to/a file.bin"
/payload payload_1KB.bin
/payload payload_100KB.bin
/payload payload_10MB.bin
/help
/quit
```

Incoming files are SHA-256 checked and acknowledged to Alice. Files Bob sends are also tracked, and Alice's receipt is checked against the exact hash Bob sent.

For unattended receive-only operation with automatic acknowledgements, use:

```bash
./run_server.sh --listen 0.0.0.0 --port 5002 --auto-reply
```

## PS-P1 security tests and benchmark

After setup, judges can run the complete mandatory suite and Objective 3 benchmark with one command:

```bash
.venv/bin/python3 security_tests.py
```

The command prints `PASS`/`FAIL` and the observed behavior for T1–T9. It writes
`results/security_tests.csv` using `security_tests_template.csv`, and writes the
benchmark measurements to `results/benchmark_results.csv`. A nonzero exit status
means at least one test or benchmark failed.

The default benchmark performs 10 successful PQC handshakes and 10 successful
classical-baseline handshakes. Use `--trials 100` for the recommended sample size.
It reports median, Q1, Q3, IQR, trial count, every serialized handshake-message
size, total handshake bytes, payload encryption/decryption time, and record
overhead. Handshakes use a local OS `socketpair`; record payload timing is local
in-process. The 12-byte per-record nonce is derived from the traffic IV and
sequence number and is not transmitted; actual serialized overhead is the
14-byte authenticated header plus the 16-byte GCM tag (30 bytes per record).

## Repeatable payload exchange with attack recovery

Start Bob first. `--runs N` counts only sessions in which Alice and Bob both
exchange and SHA-256 verify all three official payloads. If a handshake,
record, or network interruption is detected, the current connection is closed,
the event is appended to CSV, and the programs continue with a fresh session.

On Bob (`10.12.138.147`):

```bash
./run_server.sh --listen 0.0.0.0 --port 5002 --runs 10 \
  --attack-csv results/bob_attack_events.csv
```

On Alice:

```bash
./run_client.sh 10.12.138.147 --port 5002 --runs 10 \
  --attack-csv results/alice_attack_events.csv
```

Use `--runs N` on both sides. Do not combine Bob's `--runs` mode with Alice's
`--demo` or interactive mode. Authenticated text received accidentally during a
payload-only run is treated as a configuration mismatch, not as an attack.

Each CSV row records the UTC time, role, peer, protocol phase, attempt number,
completed-run count, exception type and message, security analysis, and recovery
action. Existing rows are preserved. Stop an indefinitely interrupted run with
`Ctrl+C`; Alice waits one second before reconnecting by default, configurable
with `--retry-delay`.
