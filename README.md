# Wipro Warriors — PS-P1: Quantum-Safe Secure Communication Channel

**Team members:** Siddartha, Vishnu, Musavir, Rishi, Deepika  
**Problem statement:** PS-P1 — Quantum-Safe Secure Communication Channel (QFF 2026 Phase 2, PQC track). This is the only problem statement addressed.  
**Phase 1 work reused:** none  

> This is a research prototype, not a claim of production security (see [report.md](report.md) §8).

## 1. Summary

Alice and Bob set up a **mutually authenticated, quantum-safe channel**:

* **Key establishment:** ephemeral **ML-KEM-768** (FIPS 203).
* **Authentication:** both sides sign the full handshake transcript with **ML-DSA-65** (FIPS 204), checked against **pinned trust anchors**.
* **Key derivation:** **HKDF-SHA256** (RFC 5869) derives separate keys for each direction from the hash of the whole transcript.
* **Messages:** sent as **AES-256-GCM** (SP 800-38D) records with an authenticated header and strict sequence numbers.

The **classical baseline** (X25519 + Ed25519, same HKDF and AEAD) runs through exactly the same code, so the two can be compared directly.

**Security tests:** one command runs all mandatory tests **T1–T9**, with 185 fault-injection sub-cases across the PQC, baseline and hybrid suites. They include an exhaustive bit flip in every byte of every handshake message and a full active-MITM downgrade attack. Every test passes.

**Benchmarks:**

* Handshakes: 100 per suite, in-process and over TCP loopback.
* Exact bytes per message.
* The three official payloads.
* Primitive costs.
* Optional Platform B (1 core / 128 MB) and Platform D (emulated network links).

All results are in [RESULTS.md](RESULTS.md) and the analysis is in [report.md](report.md).

<!-- AUTO:ratios -->
- **Bytes:** PQC handshake = 9,282 B vs baseline 572 B -> **16.2x** (+8,710 B per handshake; deterministic, identical on every machine).
- **Latency (in-process):** PQC median 1.492 ms vs baseline 0.422 ms -> **3.54x** (+1.070 ms).
- **Latency (TCP loopback):** PQC median 1.538 ms vs baseline 0.485 ms -> **3.17x** (+1.053 ms).
- **Record layer:** identical AES-256-GCM in both suites - 10 MB encrypt median 3.25 ms (PQC) vs 3.26 ms (classical-baseline); PQC changes only the handshake.
<!-- /AUTO:ratios -->

## 2. Setup — exact steps

Requires Python 3.10–3.13 on Windows, macOS or Linux. Nothing is compiled.

```
python -m venv .venv
# Windows: .venv\Scripts\activate          macOS/Linux: source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python common/env_check.py                 # must print READY (also writes platform_A_info.json)
```

## 3. Reproduce the principal results — exact commands

**Everything (all tables and figures, Platforms A, B and D):**

```
python run_all.py                          # ≈2–5 min on a laptop; plug in to power first
python run_all.py --quick                  # ≈1 min smoke run (20 handshakes, sampled T2, no B/D)
```

**Step by step** (each command regenerates one part of `results/`):

```
python P1_secure_channel/gen_payloads.py   # official 1 KB / 100 KB / 10 MB payloads + SHA-256 check
python run_security_tests.py               # T1–T9 (gate G4 = T1)       -> results/security_tests*.csv
python scripts/bench_handshake.py          # 100 handshakes x 3 suites x {in-process, loopback}
                                           #   -> results/handshake_results.csv, handshake_trials.csv,
                                           #      handshake_bytes.csv, primitive_timings.csv
python scripts/bench_payloads.py           # payload encrypt/decrypt   -> results/payload_results.csv
python common/run_on_platform.py --platform B -- python scripts/bench_handshake.py --out results/platform_B
python common/run_on_platform.py --platform B -- python scripts/bench_payloads.py  --out results/platform_B
python scripts/platform_d.py               # optional Platform D       -> results/platform_D/
python scripts/make_figures.py             # results/figures/*.png
python scripts/make_report.py              # refresh tables in report.md / README.md / RESULTS.md
python -m pytest                           # same T1–T9 + unit tests via pytest (optional)
```

Expected run time on Platform A: `run_security_tests.py` takes about 45 s, and the whole `run_all.py` takes about 2–5 min.

**Live demo over real TCP** (one machine with two terminals, or two machines):

```
python scripts/channel.py provision                            # identities + pinned trust stores -> keys/ (git-ignored)
python scripts/channel.py server --port 8765 --suite pqc       # terminal 1: Bob
python scripts/channel.py client --port 8765 --suite pqc       # terminal 2: Alice sends the 3 payloads, Bob returns SHA-256
python scripts/channel.py client --port 8765 --suite classical # rejected: Bob's policy is PQC-only (downgrade refused)
```

## 4. Platforms used

| Platform | Machine / profile | Evidence file |
|---|---|---|
| A (required) | team laptop as-is (CPU, cores, RAM and OS recorded automatically) | `platform_A_info.json` |
| B (optional) | 1 core, single-threaded libraries, 128 MB budget via `common/run_on_platform.py` | `platform_runs.jsonl`, `results/platform_B/` |
| D (optional) | emulated links: LAN 1 ms/100 Mbit/s, 4G 50 ms/10 Mbit/s, constrained 100 ms/1 Mbit/s, narrowband 300 ms/100 kbit/s | [platform_D.md](platform_D.md), `results/platform_D/` |

## 5. Libraries and versions

| Library | Version | Used for |
|---|---|---|
| `cryptography` | 50.0.2 | ML-KEM-768, ML-DSA-65, X25519, Ed25519, HKDF-SHA256, HMAC-SHA256, AES-256-GCM (all primitives) |
| `pqcrypto` | 1.0.0 | kit `env_check.py` self-test only |
| `psutil` | 7.2.2 | Platform A record, Platform B runner |
| `matplotlib` | 3.11.2 | figures only, in a separate process |
| `pytest` | 9.1.1 | optional test runner |

No cryptographic primitive is implemented in this repository (gate G3). Parameter sets:

* **ML-KEM-768:** ek 1184 B, ct 1088 B.
* **ML-DSA-65:** pk 1952 B, signature 3309 B. Pure mode with FIPS 204 context strings.
* **AES-256-GCM:** 96-bit nonce, 128-bit tag.
* **HKDF:** SHA-256.

## 6. Tests (command, expected behaviour, recorded result)

Command: `python run_security_tests.py`. It prints PASS/FAIL plus the observed error for every sub-case and writes `results/security_tests.csv` and `results/security_tests_detailed.csv`.

| ID | Fault injected (automated) | Expected | Result |
|---|---|---|---|
| T1 | none; 1 KB / 100 KB / 10 MB in both directions | handshake ok, identical keys, SHA-256 match | see below |
| T2 | one bit flipped in **every byte** of CH/SH/SV/SF/CV/CF (KEM pk, KEM ct, nonces, identities, key ids, algorithm IDs, signatures, MACs, headers) | abort, no session on either side | |
| T3 | bit flips in the ServerVerify / ClientVerify ML-DSA signature; random signature | `SignatureError` ← `InvalidSignature` | |
| T4 | bit flips in record ciphertext (both directions; one fragment of the 10 MB message) | `InvalidTag`, nothing released, session closed | |
| T5 | bit flips in the GCM tag and in every header (AAD) field; truncated tag | `InvalidTag` | |
| T6 | Mallory's own valid key and signature as "bob" or "alice"; copied key ids; unpinned names | rejected against the trust anchor | |
| T7 | Bob's genuine flight replayed into Carol's session; redirect to trusted Charlie; swapped role fields; signature reflected between roles | rejected (identity / transcript binding) | |
| T8 | record replay, reorder, reflection, cross-session replay; old ClientHello; old handshake against a restarted server; old server flight | rejected (**implemented**, not scoped out) | |
| T9 | suite, algorithm IDs and version rewritten in CH and SH; **active MITM downgrade to X25519+Ed25519** against a server that also accepts it | rejected; no session on either side | |

Recorded results:

<!-- AUTO:security -->
| ID | Test | Expected | PQC | CLASSICAL | HYBRID |
|---|---|---|---|---|---|
| T1 | Honest run | handshake ok + identical keys + payloads decrypt byte-exact | **PASS** (7/7) | **PASS** (7/7) | **PASS** (7/7) |
| T2 | Handshake tampering | abort, no traffic key | **PASS** (7/7) | **PASS** (7/7) | **PASS** (7/7) |
| T3 | Signature tampering | reject (InvalidSignature) | **PASS** (7/7) | **PASS** (7/7) | **PASS** (7/7) |
| T4 | Ciphertext tampering | InvalidTag, plaintext never released | **PASS** (7/7) | **PASS** (7/7) | **PASS** (7/7) |
| T5 | Tag/AAD tampering | InvalidTag | **PASS** (9/9) | **PASS** (9/9) | **PASS** (9/9) |
| T6 | Untrusted identity | reject against trust anchor | **PASS** (6/6) | **PASS** (6/6) | **PASS** (6/6) |
| T7 | Identity swap | reject via transcript/identity binding | **PASS** (5/5) | **PASS** (5/5) | **PASS** (5/5) |
| T8 | Replay | reject (implemented) | **PASS** (7/7) | **PASS** (7/7) | **PASS** (7/7) |
| T9 | Algorithm downgrade | reject | **PASS** (7/7) | **PASS** (6/6) | **PASS** (7/7) |

185/185 sub-cases passed. Command: `python run_security_tests.py`. Every sub-case with its observed error message: `results/security_tests_detailed.csv`.
<!-- /AUTO:security -->

## 7. Results

* Full tables: [RESULTS.md](RESULTS.md).
* Analysis: [report.md](report.md).
* Raw CSVs: `results/`.
* Figures: `results/figures/` — latency, bytes per message, primitive costs, Platform D.

Every measurement is labelled **local (in-process)**, **local (TCP loopback)** or **emulated network**.

## 8. Baseline used

**X25519 + Ed25519 with HKDF-SHA256 and AES-256-GCM.** It is the same protocol, messages, transcript binding and record layer as the PQC suite; only the KEM and signature calls change (`src/qsc/suites.py`). It passes the same T1–T9 tests.

## 9. Known limitations

The main limitations are:

* Trust comes from pinned keys; there is no PKI or revocation.
* Identities are sent in clear.
* The replay cache is in memory.
* There are no DoS cookies, no key update, no resumption and no 0-RTT.
* Records must arrive in order, so the protocol needs a reliable transport.
* The Platform D emulator does not model packet loss.
* Python prototype with no side-channel hardening.

Details and proposed fixes are in [report.md](report.md) §8–9.

## Repository layout

```
src/qsc/            protocol package
  suites.py         PQC / classical / hybrid suites (library wrappers only)
  wire.py           strict canonical TLV encoding
  identity.py       identities + pinned trust store
  handshake.py      Alice/Bob state machines, transcript binding, fail-closed
  keyschedule.py    transcript hash + HKDF key schedule + Finished MACs
  record.py         AES-256-GCM record layer, sequence numbers, replay protection
  transport.py      TCP framing, abort alerts, server loop
  netem.py          link emulator (Platform D)
  lab.py, benchlib.py, payloads.py   test / benchmark helpers
tests/              security_suite.py (T1–T9), pytest wrappers, unit tests
scripts/            bench_handshake.py, bench_payloads.py, platform_d.py, channel.py, make_figures.py, make_report.py
run_security_tests.py, run_all.py   one-command entry points
common/, P1_secure_channel/         organizer kit files (unchanged)
docs/PROTOCOL.md    protocol specification + threat model
results/            raw CSV/JSON + figures      report.md, RESULTS.md, platform_D.md
```
