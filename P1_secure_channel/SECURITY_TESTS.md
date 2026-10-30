# PS-P1 — Mandatory Security Test Suite

Implement every test below as an automated test (pytest, unittest or a script) that judges can run with
**one command** listed in your README. Each test must print `PASS`/`FAIL` and the observed behaviour.
Record results in `results/security_tests.csv` (template: `security_tests_template.csv`).

| ID | Test | Attack / fault injected | Expected result |
|---|---|---|---|
| T1 | Honest run | none | Handshake completes, both sides derive identical traffic keys, the 3 official payloads decrypt byte-exact (check SHA-256) |
| T2 | Handshake tampering | flip one bit in any handshake message (KEM public key, KEM ciphertext, nonce, identity, algorithm ID) | Handshake **aborts** (signature/transcript check fails); no traffic key is used |
| T3 | Signature tampering | flip one bit in the ML-DSA signature | Rejected with signature-verification failure |
| T4 | Ciphertext tampering | flip one bit in an application-record ciphertext | AES-GCM `InvalidTag`; plaintext never released |
| T5 | Tag / AAD tampering | modify the GCM tag or the authenticated header | `InvalidTag` |
| T6 | Untrusted identity | attacker sends its own valid ML-DSA key and signature (not the pinned / authenticated key) | Rejected: key does not match the trust anchor |
| T7 | Identity swap | replay Bob's genuine signed message in a session that names a different peer, or swap the roles | Rejected through transcript / identity binding |
| T8 | Replay | resend an earlier application record, or replay an old handshake | Rejected (sequence number / nonce / fresh randomness), **or** a clearly documented limitation if you do not implement replay protection |
| T9 | Algorithm downgrade | change the advertised algorithm identifiers in the transcript | Rejected, because the algorithm choices are bound to the signed transcript |

T1–T7 and T9 are mandatory. T8 is mandatory to **attempt or explicitly scope out**.

## Benchmark rules (Objective 3)

- At least **10 successful handshakes** with the same setup (100 recommended). Report **median** latency, IQR and trial count.
- Report the **actual serialised bytes** per handshake message and in total, and per-record overhead (nonce + tag + header).
- Encrypt and decrypt the three official payloads (1 KB, 100 KB, 10 MB) and report the time and overhead for each.
- State whether the measurement is **local (in-process / loopback)** or a **real network** run. Both are allowed; just label it.
- **Baseline:** run the same flow with classical X25519 + Ed25519 (same KDF and AEAD) and compare latency and bytes.
