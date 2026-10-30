#!/usr/bin/env python3
"""PS-P1 mandatory security tests and objective-3 benchmark.

Run from the repository root with::

    .venv/bin/python3 security_tests.py

The suite deliberately uses the production handshake and record-layer functions
from bob.py.  Faults are injected at the byte-serialized Conn boundary.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import os
from pathlib import Path
import socket
import statistics
import sys
import threading
import time
import traceback

try:
    import bob as q
except (ImportError, SystemExit) as exc:
    print(f"FAIL dependency check: {exc}")
    print("Observed: install requirements first with '.venv/bin/python3 -m pip install -r requirements.txt'.")
    raise SystemExit(2)


ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
PAYLOAD_PATHS = (
    ROOT / "payload_1KB.bin",
    ROOT / "payload_100KB.bin",
    ROOT / "payload_10MB.bin",
)
HANDSHAKE_TYPES = {q.CH, q.SH, q.SV, q.SF, q.CV, q.CF}


class QuietLog(q.Log):
    def __init__(self, who="TEST"):
        super().__init__(who, enabled=False)


def frames(data: bytes) -> list[bytes]:
    """Split a concatenated batch of encoded handshake messages."""
    out, pos = [], 0
    while pos < len(data):
        if data[pos] not in q.MSG_NAMES:
            raise ValueError(f"not a handshake frame at offset {pos}")
        body_len = int.from_bytes(data[pos + 1:pos + 5], "big")
        end = pos + 5 + body_len
        if end > len(data):
            raise ValueError("truncated handshake batch")
        out.append(data[pos:end])
        pos = end
    return out


class ObservedConn:
    """Conn decorator that records and optionally mutates sent handshake frames."""

    def __init__(self, conn: q.Conn, mutate=None):
        self.inner = conn
        self.mutate = mutate
        self.observed: list[bytes] = []

    @property
    def sent(self):
        return self.inner.sent

    @property
    def received(self):
        return self.inner.received

    def send(self, data):
        batch = frames(data) if data and data[0] in HANDSHAKE_TYPES else [data]
        changed = []
        for frame in batch:
            self.observed.append(frame)
            changed.append(self.mutate(frame) if self.mutate else frame)
        self.inner.send(b"".join(changed))

    def __getattr__(self, name):
        return getattr(self.inner, name)


def replace_field(message: bytes, field: int, value: bytes) -> bytes:
    start, end = q.field_span(message, field)
    if len(value) != end - start:
        raise ValueError("replacement must preserve serialized field length")
    return message[:start] + value + message[end:]


def flip_field(message: bytes, field: int, offset=0) -> bytes:
    start, end = q.field_span(message, field)
    if not 0 <= offset < end - start:
        raise ValueError("field offset out of range")
    return q.flip_bit(message, start + offset)


def mutate_once(message_type, transform):
    used = False

    def mutate(message):
        nonlocal used
        if not used and message[0] == message_type:
            used = True
            return transform(message)
        return message

    return mutate


def identities():
    alice_name, alice_ids = q.load_identity(ROOT / "Alice" / "alice.key.json")
    bob_name, bob_ids = q.load_identity(ROOT / "bob.key.json")
    alice_pins = {alg: pair[1] for alg, pair in alice_ids.items()}
    bob_pins = {alg: pair[1] for alg, pair in bob_ids.items()}
    return alice_name, alice_ids, alice_pins, bob_name, bob_ids, bob_pins


def handshake(suite=q.PQC, client_mutate=None, server_mutate=None, replay_cache=None):
    """Run both production handshake endpoints over a local socketpair."""
    alice_name, alice_ids, alice_pins, bob_name, bob_ids, bob_pins = identities()
    left, right = socket.socketpair()
    client = ObservedConn(q.Conn(left), client_mutate)
    server = ObservedConn(q.Conn(right), server_mutate)
    result, errors = {}, {}

    def run_server():
        try:
            pins = {(alice_name, alg): pk for alg, pk in alice_pins.items()}
            result["server"] = q.server_handshake(
                server, bob_name, bob_ids, pins, {suite.sid},
                replay_cache if replay_cache is not None else q.ReplayCache(), QuietLog("SERVER")
            )
        except BaseException as exc:  # retained for attack assertions
            errors["server"] = exc

    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()
    started = time.perf_counter_ns()
    try:
        result["client"] = q.client_handshake(
            client, alice_name, alice_ids, bob_name, bob_pins, suite, QuietLog("CLIENT")
        )
    except BaseException as exc:  # retained for attack assertions
        errors["client"] = exc
    elapsed_ms = (time.perf_counter_ns() - started) / 1e6
    thread.join(timeout=30)
    if thread.is_alive():
        client.close()
        server.close()
        raise TimeoutError("handshake thread did not finish")
    client.close()
    server.close()
    return result, errors, elapsed_ms, client.observed + server.observed


def require_honest(suite=q.PQC):
    result, errors, elapsed, observed = handshake(suite)
    if errors:
        raise AssertionError(", ".join(f"{side}: {type(exc).__name__}: {exc}" for side, exc in errors.items()))
    if set(result) != {"client", "server"}:
        raise AssertionError("both handshake endpoints did not complete")
    if result["client"].keys != result["server"].keys:
        raise AssertionError("client and server traffic key dictionaries differ")
    return result["client"], result["server"], elapsed, observed


def fresh_receiver(session: q.Session) -> q.Session:
    role = "server" if session.role == "client" else "client"
    return q.Session(role, session.suite, session.peer, session.keys, session.th)


def record_roundtrip(sender: q.Session, receiver: q.Session, payload: bytes):
    clear = bytearray()
    records = sender.send_message(payload)
    for record in records:
        _ctype, _flags, chunk = receiver.open(record)
        clear.extend(chunk)
    return bytes(clear), records


def exception_named(errors, *names):
    return next((exc for exc in errors.values() if type(exc).__name__ in names), None)


def t1_honest():
    client, server, elapsed, _ = require_honest(q.PQC)
    details = []
    for path in PAYLOAD_PATHS:
        source = path.read_bytes()
        clear, records = record_roundtrip(client, server, source)
        expected = hashlib.sha256(source).hexdigest()
        actual = hashlib.sha256(clear).hexdigest()
        if clear != source or actual != expected:
            raise AssertionError(f"{path.name} differed after decryption")
        details.append(f"{path.name} SHA-256={actual}, {len(records)} record(s)")
    return f"handshake completed in {elapsed:.3f} ms; traffic keys identical; " + "; ".join(details)


def t2_handshake_tamper():
    mutation = mutate_once(q.SH, lambda message: flip_field(message, q.F_SERVER_NONCE))
    result, errors, _elapsed, _ = handshake(q.PQC, server_mutate=mutation)
    exc = exception_named(errors, "SignatureError", "FinishedError")
    if exc is None or result:
        raise AssertionError(f"expected transcript/signature abort, got {errors!r}")
    return f"server nonce bit flipped; client aborted with {type(exc).__name__}: {exc}; no traffic session returned by either side"


def t3_signature_tamper():
    mutation = mutate_once(q.SV, lambda message: flip_field(message, q.F_SIGNATURE))
    result, errors, _elapsed, _ = handshake(q.PQC, server_mutate=mutation)
    exc = exception_named(errors, "SignatureError")
    if exc is None or result:
        raise AssertionError(f"expected SignatureError, got {errors!r}")
    return f"ML-DSA signature bit flipped; rejected with {type(exc).__name__}: {exc}"


def t4_ciphertext_tamper():
    client, _server, _elapsed, _ = require_honest(q.PQC)
    receiver = fresh_receiver(client)
    record = client.seal(b"plaintext must not escape")
    tampered = q.flip_bit(record, q.REC_HDR.size)
    released = False
    try:
        receiver.open(tampered)
        released = True
    except q.RecordAuthError as exc:
        if released:
            raise AssertionError("plaintext was released")
        return f"ciphertext bit flipped; {exc}; plaintext released={released}"
    raise AssertionError("tampered ciphertext was accepted")


def t5_tag_and_aad_tamper():
    client, _server, _elapsed, _ = require_honest(q.PQC)
    failures = []
    for label, index in (("tag", -1), ("AAD header", 1)):
        receiver = fresh_receiver(client)
        record = client.seal(label.encode())
        # A fresh sender sequence is reflected in the receiver expectation.
        receiver.rx[2] = int.from_bytes(record[2:10], "big")
        try:
            receiver.open(q.flip_bit(record, index))
        except q.RecordAuthError as exc:
            failures.append(f"{label}: {exc}")
        else:
            raise AssertionError(f"tampered {label} was accepted")
    return "; ".join(failures)


def t6_untrusted_identity():
    _an, _ai, alice_pins, _bn, _bi, _bp = identities()
    attacker = q.mldsa.MLDSA65PrivateKey.generate()
    attacker_pk = attacker.public_key().public_bytes_raw()
    proof = q.sig_sign("ML-DSA-65", attacker, b"attacker transcript", q.CTX_CLIENT)
    q.sig_verify("ML-DSA-65", attacker_pk, proof, b"attacker transcript", q.CTX_CLIENT)
    pins = {("alice", alg): pk for alg, pk in alice_pins.items()}
    try:
        q.lookup_pin(pins, "alice", "ML-DSA-65", q.key_id(attacker_pk))
    except q.UntrustedIdentity as exc:
        return f"attacker ML-DSA signature self-valid, but attacker key rejected against Alice pin: {exc}"
    raise AssertionError("attacker identity matched the trust anchor")


def t7_identity_swap():
    mutation = mutate_once(q.SH, lambda message: replace_field(message, q.F_SERVER_ID, b"eve"))
    result, errors, _elapsed, _ = handshake(q.PQC, server_mutate=mutation)
    exc = exception_named(errors, "IdentityMismatch")
    if exc is None or result:
        raise AssertionError(f"expected IdentityMismatch, got {errors!r}")
    return f"signed Bob flight relabelled as peer 'eve'; rejected with {type(exc).__name__}: {exc}"


def t8_replay():
    client, _server, _elapsed, _ = require_honest(q.PQC)
    receiver = fresh_receiver(client)
    record = client.seal(b"one-time record")
    receiver.open(record)
    try:
        receiver.open(record)
    except q.ReplayError as exc:
        return f"application record replay rejected before decryption: {exc}"
    raise AssertionError("replayed record was accepted")


def t9_algorithm_downgrade():
    def downgrade(message):
        original = q.decode(message, q.CH)[q.F_ALGS]
        changed = b"X" + original[1:]
        return replace_field(message, q.F_ALGS, changed)

    result, errors, _elapsed, _ = handshake(q.PQC, client_mutate=mutate_once(q.CH, downgrade))
    exc = exception_named(errors, "DowngradeError")
    if exc is None or result:
        raise AssertionError(f"expected DowngradeError, got {errors!r}")
    return f"ClientHello algorithm identifier bit changed; rejected with {type(exc).__name__}: {exc}"


TESTS = (
    ("T1", "Honest run", t1_honest),
    ("T2", "Handshake tampering", t2_handshake_tamper),
    ("T3", "Signature tampering", t3_signature_tamper),
    ("T4", "Ciphertext tampering", t4_ciphertext_tamper),
    ("T5", "Tag / AAD tampering", t5_tag_and_aad_tamper),
    ("T6", "Untrusted identity", t6_untrusted_identity),
    ("T7", "Identity swap", t7_identity_swap),
    ("T8", "Replay", t8_replay),
    ("T9", "Algorithm downgrade", t9_algorithm_downgrade),
)


def percentile(values, p):
    ordered = sorted(values)
    position = (len(ordered) - 1) * p
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def benchmark_suite(suite, trials):
    latencies, sample_frames = [], None
    for _ in range(trials):
        _client, _server, elapsed, observed = require_honest(suite)
        latencies.append(elapsed)
        sample_frames = observed
    sizes = {q.MSG_NAMES[message[0]]: len(message) for message in sample_frames}
    return {
        "suite": suite.label,
        "trials": trials,
        "median_ms": statistics.median(latencies),
        "q1_ms": percentile(latencies, 0.25),
        "q3_ms": percentile(latencies, 0.75),
        "iqr_ms": percentile(latencies, 0.75) - percentile(latencies, 0.25),
        "message_sizes": sizes,
        "total_bytes": sum(sizes.values()),
    }


def benchmark_payloads():
    client, _server, _elapsed, _ = require_honest(q.PQC)
    rows = []
    for path in PAYLOAD_PATHS:
        data = path.read_bytes()
        sender = q.Session("client", q.PQC, "bob", client.keys, client.th)
        receiver = q.Session("server", q.PQC, "alice", client.keys, client.th)
        start = time.perf_counter_ns()
        records = sender.send_message(data)
        encrypt_ms = (time.perf_counter_ns() - start) / 1e6
        start = time.perf_counter_ns()
        clear = b"".join(receiver.open(record)[2] for record in records)
        decrypt_ms = (time.perf_counter_ns() - start) / 1e6
        if clear != data:
            raise AssertionError(f"benchmark roundtrip failed for {path.name}")
        wire_bytes = sum(map(len, records))
        rows.append({
            "payload": path.name,
            "payload_bytes": len(data),
            "records": len(records),
            "wire_bytes": wire_bytes,
            "overhead_bytes": wire_bytes - len(data),
            "encrypt_ms": encrypt_ms,
            "decrypt_ms": decrypt_ms,
            "sha256": hashlib.sha256(clear).hexdigest(),
        })
    return rows


def write_security_results(rows):
    RESULTS.mkdir(exist_ok=True)
    path = RESULTS / "security_tests.csv"
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=("id", "test", "status", "observed_behavior"))
        writer.writeheader()
        writer.writerows(rows)
    return path


def write_benchmarks(handshakes, payloads):
    path = RESULTS / "benchmark_results.csv"
    fields = ("category", "suite_or_payload", "trials_or_records", "median_or_encrypt_ms",
              "q1_or_decrypt_ms", "q3_ms", "iqr_ms", "serialized_bytes", "overhead_bytes", "detail")
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for item in handshakes:
            writer.writerow({
                "category": "handshake_local_socketpair",
                "suite_or_payload": item["suite"],
                "trials_or_records": item["trials"],
                "median_or_encrypt_ms": f'{item["median_ms"]:.6f}',
                "q1_or_decrypt_ms": f'{item["q1_ms"]:.6f}',
                "q3_ms": f'{item["q3_ms"]:.6f}',
                "iqr_ms": f'{item["iqr_ms"]:.6f}',
                "serialized_bytes": item["total_bytes"],
                "overhead_bytes": "",
                "detail": "; ".join(f"{name}={size} B" for name, size in item["message_sizes"].items()),
            })
        pqc, classical = handshakes
        writer.writerow({
            "category": "baseline_comparison",
            "suite_or_payload": "PQC / CLASSICAL",
            "trials_or_records": f'{pqc["trials"]} each',
            "median_or_encrypt_ms": f'{pqc["median_ms"] / classical["median_ms"]:.3f}x latency',
            "q1_or_decrypt_ms": "",
            "q3_ms": "",
            "iqr_ms": "",
            "serialized_bytes": pqc["total_bytes"] - classical["total_bytes"],
            "overhead_bytes": "",
            "detail": (f'PQC median {pqc["median_ms"]:.6f} ms vs classical {classical["median_ms"]:.6f} ms; '
                       f'PQC {pqc["total_bytes"]} B vs classical {classical["total_bytes"]} B '
                       f'({pqc["total_bytes"] / classical["total_bytes"]:.3f}x bytes)'),
        })
        for item in payloads:
            writer.writerow({
                "category": "record_local_in_process",
                "suite_or_payload": item["payload"],
                "trials_or_records": item["records"],
                "median_or_encrypt_ms": f'{item["encrypt_ms"]:.6f}',
                "q1_or_decrypt_ms": f'{item["decrypt_ms"]:.6f}',
                "q3_ms": "",
                "iqr_ms": "",
                "serialized_bytes": item["wire_bytes"],
                "overhead_bytes": item["overhead_bytes"],
                "detail": f'payload={item["payload_bytes"]} B; SHA-256={item["sha256"]}',
            })
        writer.writerow({
            "category": "record_overhead",
            "suite_or_payload": "AES-256-GCM",
            "trials_or_records": "per record",
            "median_or_encrypt_ms": "",
            "q1_or_decrypt_ms": "",
            "q3_ms": "",
            "iqr_ms": "",
            "serialized_bytes": q.REC_HDR.size + 16,
            "overhead_bytes": q.REC_HDR.size + 16,
            "detail": "14 B authenticated header + 16 B tag; 12 B nonce derived from IV XOR sequence and not serialized",
        })
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=10, help="successful handshakes per suite (minimum 10)")
    parser.add_argument("--skip-benchmark", action="store_true", help="run only T1-T9")
    args = parser.parse_args()
    if not args.skip_benchmark and args.trials < 10:
        parser.error("--trials must be at least 10 under the benchmark rules")

    rows, all_pass = [], True
    for test_id, name, function in TESTS:
        try:
            observed = function()
            status = "PASS"
        except BaseException as exc:
            status = "FAIL"
            observed = f"{type(exc).__name__}: {exc}"
            if os.environ.get("PSP1_TRACEBACK"):
                traceback.print_exc()
            all_pass = False
        print(f"{status} {test_id} {name}: {observed}", flush=True)
        rows.append({"id": test_id, "test": name, "status": status, "observed_behavior": observed})

    security_path = write_security_results(rows)
    print(f"Security results: {security_path.relative_to(ROOT)}")

    if not args.skip_benchmark:
        try:
            handshakes = [benchmark_suite(q.PQC, args.trials), benchmark_suite(q.CLASSICAL, args.trials)]
            payloads = benchmark_payloads()
            benchmark_path = write_benchmarks(handshakes, payloads)
            for item in handshakes:
                print(f"PASS BENCHMARK {item['suite']}: n={item['trials']}, median={item['median_ms']:.3f} ms, "
                      f"IQR={item['iqr_ms']:.3f} ms, handshake={item['total_bytes']} serialized B")
            for item in payloads:
                print(f"PASS PAYLOAD {item['payload']}: encrypt={item['encrypt_ms']:.3f} ms, "
                      f"decrypt={item['decrypt_ms']:.3f} ms, overhead={item['overhead_bytes']} B")
            print(f"Benchmark results: {benchmark_path.relative_to(ROOT)}")
        except BaseException as exc:
            all_pass = False
            print(f"FAIL BENCHMARK: {type(exc).__name__}: {exc}")
            if os.environ.get("PSP1_TRACEBACK"):
                traceback.print_exc()

    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
