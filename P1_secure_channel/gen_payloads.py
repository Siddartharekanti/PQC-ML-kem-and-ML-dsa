"""
QFF 2026 Phase 2 - PS-P1 official test payloads (same bytes on every machine).

    python P1_secure_channel/gen_payloads.py            -> writes payloads/ and checks SHA-256

Payloads: payload_1KB.bin (1,024 B), payload_100KB.bin (102,400 B), payload_10MB.bin (10,485,760 B)
Content : SHAKE-256("QFF2026-P1-<name>") expanded to the required length.
"""
import hashlib
import os

SIZES = {"payload_1KB.bin": 1024, "payload_100KB.bin": 100 * 1024, "payload_10MB.bin": 10 * 1024 * 1024}
EXPECTED = {}  # filled below from payload_sha256.txt


def make(name, n):
    return hashlib.shake_256(f"QFF2026-P1-{name}".encode()).digest(n)


if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    out = os.path.join(here, "payloads")
    os.makedirs(out, exist_ok=True)
    for line in open(os.path.join(here, "payload_sha256.txt")):
        h, name = line.split()
        EXPECTED[name] = h
    ok = True
    for name, n in SIZES.items():
        data = make(name, n)
        with open(os.path.join(out, name), "wb") as f:
            f.write(data)
        h = hashlib.sha256(data).hexdigest()
        good = h == EXPECTED.get(name)
        ok &= good
        print(f"{'OK  ' if good else 'FAIL'} {name:20s} {n:>10,d} B  sha256={h}")
    print("All payloads match the official hashes." if ok else "Hash mismatch - re-download the kit.")
