# Technical Report — Wipro Warriors — PS-P1: Quantum-Safe Secure Communication Channel

**Team members:** Siddartha, Vishnu, Musavir, Rishi, Deepika  
**Problem statement:** PS-P1 — Quantum-Safe Secure Communication Channel (QFF 2026 Phase 2, PQC track)  

> **This is a research prototype, not a claim of production security.** It shows a quantum-safe design and measures what it costs. It has not been audited, hardened against side channels, or tested for interoperability.

Tables between `AUTO` markers are regenerated from `results/*.csv` by `python scripts/make_report.py`, which `python run_all.py` runs as its last step. They always match the committed raw data.

## 1. Problem and scope

**What we built:**

* `qsc`, a Python package that gives Alice and Bob a mutually authenticated, quantum-safe channel:
  * ML-KEM-768 for key establishment
  * ML-DSA-65 for authentication
  * HKDF-SHA256 for key derivation
  * AES-256-GCM records
* The same protocol with the required classical baseline, X25519 + Ed25519. It uses the same code path, HKDF and AEAD.
* An automated suite of 185 attack sub-cases covering T1–T9, run with one command.
* Benchmarks: in-process and TCP loopback handshakes, the three official payloads, and primitive costs.
* Optional extras:
  * Platform B, the kit's constrained profile.
  * Platform D, emulated network links.
  * A hybrid X25519+ML-KEM-768 suite, used to support the deployment recommendation.

**What we did not build:**

* Certificates or PKI. Trust comes from pinned keys.
* Identity hiding.
* 0-RTT, session resumption and key update.
* Packet-loss modelling.
* Any production hardening.

The full protocol specification is in `docs/PROTOCOL.md`.

## 2. Design decisions (with alternatives considered)

| Decision | Choice | Why / alternatives considered |
|---|---|---|
| Handshake shape | SIGMA / TLS 1.3 style, 1 RTT, signed transcript plus Finished MACs | *Static KEM keys for authentication (KEMTLS)* would make messages smaller, but the task requires ML-DSA, and pins of static KEM keys complicate rotation. *Signing only the KEM key* leaves nonces, identities and algorithms unbound, which leads to misbinding and downgrade. |
| Authentication | **Mutual** (both sides sign) | The task wants authenticated parties. Server-only authentication would let any client connect, and an active downgrade MITM could finish the server side (test T9, last case). Cost: one extra 3,309 B signature from client to server, plus one Sign and one Verify. |
| Trust anchor | Pinned ML-DSA public keys; the wire carries only 32 B key ids | Sending the 1,952 B public key (as a raw key or inside a certificate) would add ≥3.9 kB per handshake and gain nothing with pinning. Key ids let the receiver report "wrong key" clearly, while verification always uses the local pin. |
| Transcript binding | SHA-256 over the exact serialized bytes of all messages so far; canonical TLV encoding | Hashing raw bytes with a strict parser means a bit flip either fails parsing or changes the signed hash. An exhaustive campaign flipping one bit in **every byte** of every message (9,420 handshakes for PQC) confirmed this. |
| Signature domain separation | Distinct FIPS 204 context strings for the server and client roles | Stops a signature being reflected or reused across roles (T7). |
| Key schedule | HKDF-Extract(nonce_A‖nonce_B, ss), then labelled Expand calls bound to the transcript hash | This follows TLS 1.3. The per-session salt and transcript-bound labels give each session unique keys. Traffic keys depend on TH(CH..CF), which includes both signatures. |
| Keys per direction | Separate key and IV for c2s and s2c | Rules out reflection attacks and nonce collisions between the two directions (T8). |
| Nonce strategy | `iv XOR seq`, never transmitted; strict in-order `seq` | Deterministic, so no risk of a collision between random 96-bit nonces. It saves 12 B per record compared with an explicit nonce, and it gives replay protection for free. An alternative is a sliding replay window for datagram transport. |
| Record size | 16 KiB fragments (TLS-like); a message is released only after all fragments authenticate | Overhead stays bounded at 0.18 % and memory stays bounded. One record per message would cost only 30 B, but needs the whole message in memory. Both are measured. |
| Failure behaviour | Fail-closed state machines; alert then close; secrets dropped | Prevents oracle-style probing and any use of half-established keys. |
| Library | `cryptography` 50.0.2 only, the organizer reference build | A vetted implementation of FIPS 203/204 and the classical primitives (gate G3). |

## 3. Trust and threat model

**Trust model:**

* Authentication is **mutual**.
* Alice and Bob each have a long-term ML-DSA-65 key pair (Ed25519 for the baseline).
* Each endpoint is provisioned out of band with its peer's public key, pinned by name and algorithm.
* Nothing received over the network is trusted on its own.

**Attacker.** A Dolev–Yao attacker controls the network:

* It reads, drops, injects, replays, reorders and modifies traffic.
* It holds its own valid keys for every algorithm.
* It knows all public keys and key ids.

| Threat | How it is defeated | Evidence |
|---|---|---|
| **MITM** substituting ephemeral keys or ciphertexts | Both signatures cover the ephemeral ML-KEM key and the ciphertext; verification uses pinned keys | T2 (every byte flipped), T6 |
| Impersonation using the attacker's own valid key and signature | Key id and signature are checked against the pinned anchor; this works in both directions | T6 (6 cases) |
| Identity misbinding / role swap / signature reuse | Both identities in CH and SH, checked against the intended peer; role-specific contexts | T7 (5 cases) |
| **Replay** of records, old handshakes, cross-session records, reflection | Sequence numbers, per-direction keys, fresh nonces and KEM keys, ClientHello nonce cache | T8 (7 cases) |
| **Downgrade** of suite, algorithm IDs or version, including a full active MITM against a server that also accepts classical | Strict policy, suite echo check, signed algorithm IDs, mutual authentication | T9 (7 cases) |
| Tampering with record ciphertext, tag or header | AES-256-GCM with the header as AAD; fail-closed | T4, T5 |
| Harvest now, decrypt later | ML-KEM-768 ephemeral key establishment; AES-256 keeps about 128-bit security against Grover | design |

Out of scope:

* A compromised endpoint.
* Side channels.
* Denial of service. Bob runs one Encaps and one Sign before he has authenticated the client; see §8.

## 4. Validation

`python run_security_tests.py` runs every test on the PQC suite, the classical baseline and the hybrid extension. For each sub-case it prints PASS/FAIL and the exact error it observed. Results go to `results/security_tests.csv` (organizer columns) and `results/security_tests_detailed.csv` (all sub-cases). `python -m pytest` runs the same tests plus unit tests.

Every fault is **actually injected**. A man-in-the-middle hook edits the serialized bytes, or a forged peer is built from the attacker's real keys. Each test checks both the *type* of rejection and that **no session exists** on either side.

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

**Failure behaviour observed:**

* **T2:** all 9,420 tampered PQC handshakes aborted. Together they flip one bit in every one of the 9,282 bytes, plus extra flips at the start, middle and end of each field. Errors seen:
  * `SignatureError` for changed values inside signed fields.
  * `DecodeError` for headers and lengths.
  * `DowngradeError` for suite, version and algorithm IDs.
  * `UntrustedIdentity` / `IdentityMismatch` for names and key ids.
  * `KEMError` when a flipped ML-KEM key fails the FIPS 203 modulus check.
  * `FinishedError` for Finished MACs.

  A no-fault control run inside T2 proves the harness itself can complete a handshake.
* **T4 / T5:** every change to the ciphertext, tag or any header byte raised `InvalidTag`. The session closed, and later genuine records were refused (`SessionClosed`). Corrupting one fragment (record 300 of 640) of the 10 MB message released no part of it.
* **T8:** record replay is rejected *before* decryption (`ReplayError`). Reordering, reflection and cross-session replay fail with `InvalidTag`. A byte-exact old ClientHello is caught by the nonce cache. Against a restarted Bob with an empty cache, the old handshake still cannot complete, because the old ClientVerify does not verify over the new transcript, which has fresh `nonce_B` and `ct`.
* **T9, active downgrade:** Bob is set to also accept the classical suite. Mallory rewrites Alice's ClientHello to X25519 + Ed25519 using her own X25519 share. Bob answers, because he cannot yet tell. Alice rejects the reply (`DowngradeError`: not the suite she offered). Mallory, who knows the X25519 secret, can compute valid Finished MACs, but she cannot produce Alice's signature, so Bob rejects with `SignatureError`. Neither side has a session. This is why mutual authentication matters.

## 5. Performance results

All measurements use `time.perf_counter_ns()` with warm-up trials and the garbage collector disabled, the same method as the kit's `common/measure.py`. We report the median as the main figure, plus IQR, p95 and n. Each row says whether the measurement is **local, in-process** (both endpoints in one process, no sockets: pure protocol cost) or **local, TCP loopback** (Bob in a separate process; real serialization and socket I/O). 100 handshakes per suite and mode, all successful.

<!-- AUTO:platform -->
| Item | Value |
|---|---|
| Platform | A (team laptop/desktop, as-is) |
| OS | Darwin 27.0.0 (arm64) |
| CPU | arm, 8 physical / 8 logical cores |
| RAM | 8.0 GB |
| Python | 3.12.13 (CPython) |
| Libraries | cryptography 50.0.2, pqcrypto 1.0.0, psutil 7.2.2 |
| On battery | True |
| Recorded | 2026-10-29 14:52:44 |
<!-- /AUTO:platform -->

### 5.1 Handshake latency, bytes, success counts

<!-- AUTO:handshake -->
| Suite | Measurement | OK / trials | Median ms | IQR ms | p95 ms | C->S B | S->C B | Total B |
|---|---|---|---|---|---|---|---|---|
| PQC (ML-KEM-768 + ML-DSA-65) | local (in-process) | 100/100 | 1.492 | 0.630 | 2.794 | 4689 | 4593 | **9282** |
| PQC (ML-KEM-768 + ML-DSA-65) | local (TCP loopback 127.0.0.1) | 100/100 | 1.506 | 0.733 | 3.093 | 4689 | 4593 | **9282** |
| Baseline (X25519 + Ed25519) | local (in-process) | 100/100 | 0.418 | 0.014 | 0.452 | 286 | 286 | **572** |
| Baseline (X25519 + Ed25519) | local (TCP loopback 127.0.0.1) | 100/100 | 0.444 | 0.015 | 0.510 | 286 | 286 | **572** |
| Hybrid ext. (X25519+ML-KEM-768 + ML-DSA-65) | local (in-process) | 100/100 | 1.825 | 0.974 | 2.965 | 4728 | 4632 | **9360** |
| Hybrid ext. (X25519+ML-KEM-768 + ML-DSA-65) | local (TCP loopback 127.0.0.1) | 100/100 | 1.630 | 0.637 | 3.148 | 4728 | 4632 | **9360** |
<!-- /AUTO:handshake -->

Split of the in-process compute time between the two endpoints:

<!-- AUTO:compute -->
| Suite | Alice compute median ms | Bob compute median ms |
|---|---|---|
| PQC (ML-KEM-768 + ML-DSA-65) | 0.735 | 0.661 |
| Baseline (X25519 + Ed25519) | 0.208 | 0.209 |
| Hybrid ext. (X25519+ML-KEM-768 + ML-DSA-65) | 0.811 | 0.808 |
<!-- /AUTO:compute -->

![Handshake latency](results/figures/fig1_handshake_latency.png)

### 5.2 Bytes per handshake message

These are the exact serialized sizes, which are the same on every machine. Fields are split into cryptographic material (keys, ciphertexts, signatures, MACs, nonces, key ids), identities and algorithm strings, and framing (5 B per message header plus 3 B per field).

<!-- AUTO:bytes -->
| Message | Direction | PQC B | CLASSICAL B | HYBRID B | PQC field sizes (B) |
|---|---|---|---|---|---|
| CH ClientHello | client->server | 1332 | 174 | 1371 | version=1, suite_id=2, algorithm_ids=44, client_identity=5, client_key_id=32, server_identity=3, client_nonce=32, kem_public_key=1184 |
| SH ServerHello | server->client | 1236 | 174 | 1275 | version=1, suite_id=2, algorithm_ids=44, server_identity=3, server_key_id=32, client_identity=5, server_nonce=32, kem_ciphertext=1088 |
| SV ServerVerify | server->client | 3317 | 72 | 3317 | signature=3309 |
| SF ServerFinished | server->client | 40 | 40 | 40 | finished_mac=32 |
| CV ClientVerify | client->server | 3317 | 72 | 3317 | signature=3309 |
| CF ClientFinished | client->server | 40 | 40 | 40 | finished_mac=32 |
| **Total** |  | **9,282** | **572** | **9,360** |  |
<!-- /AUTO:bytes -->

![Bytes per message](results/figures/fig2_handshake_bytes.png)

Per-record overhead: 14 B header (type, flags, seq, length) + 16 B GCM tag + 0 B nonce (derived from the IV and seq) = **30 B per record**.

### 5.3 Official payloads

Encryption and decryption run inside an established session. Each decrypted payload's SHA-256 is checked against `payload_sha256.txt`. Two record sizes are shown: 16 KiB fragments (the default) and the whole payload as one record.

<!-- AUTO:payloads -->
| Session | Payload | Plaintext B | Record size | Records | Wire B | Overhead B | Trials | Enc median ms | Dec median ms | Enc MB/s | Dec MB/s | SHA-256 match |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| PQC (ML-KEM-768 + ML-DSA-65) | payload_1KB.bin | 1,024 | 16384 | 1 | 1,054 | 30 (2.93 %) | 200 | 0.0034 | 0.0023 | 301.6 | 446.8 | yes |
| PQC (ML-KEM-768 + ML-DSA-65) | payload_100KB.bin | 102,400 | 16384 | 7 | 102,610 | 210 (0.205 %) | 100 | 0.0339 | 0.0299 | 3019.2 | 3427.6 | yes |
| PQC (ML-KEM-768 + ML-DSA-65) | payload_10MB.bin | 10,485,760 | 16384 | 640 | 10,504,960 | 19200 (0.183 %) | 15 | 3.4403 | 3.4317 | 3047.9 | 3055.6 | yes |
| PQC (ML-KEM-768 + ML-DSA-65) | payload_1KB.bin | 1,024 | 1024 | 1 | 1,054 | 30 (2.93 %) | 200 | 0.0079 | 0.0032 | 130.0 | 319.2 | yes |
| PQC (ML-KEM-768 + ML-DSA-65) | payload_100KB.bin | 102,400 | 102400 | 1 | 102,430 | 30 (0.029 %) | 100 | 0.0289 | 0.0238 | 3546.3 | 4296.5 | yes |
| PQC (ML-KEM-768 + ML-DSA-65) | payload_10MB.bin | 10,485,760 | 10485760 | 1 | 10,485,790 | 30 (0.0 %) | 15 | 2.2452 | 1.8839 | 4670.2 | 5565.9 | yes |
| Baseline (X25519 + Ed25519) | payload_1KB.bin | 1,024 | 16384 | 1 | 1,054 | 30 (2.93 %) | 200 | 0.0035 | 0.0023 | 296.1 | 438.9 | yes |
| Baseline (X25519 + Ed25519) | payload_100KB.bin | 102,400 | 16384 | 7 | 102,610 | 210 (0.205 %) | 100 | 0.0394 | 0.0319 | 2602.0 | 3210.4 | yes |
| Baseline (X25519 + Ed25519) | payload_10MB.bin | 10,485,760 | 16384 | 640 | 10,504,960 | 19200 (0.183 %) | 15 | 3.2304 | 3.2832 | 3246.0 | 3193.8 | yes |
| Baseline (X25519 + Ed25519) | payload_1KB.bin | 1,024 | 1024 | 1 | 1,054 | 30 (2.93 %) | 200 | 0.0038 | 0.0025 | 271.5 | 409.6 | yes |
| Baseline (X25519 + Ed25519) | payload_100KB.bin | 102,400 | 102400 | 1 | 102,430 | 30 (0.029 %) | 100 | 0.0235 | 0.0200 | 4349.7 | 5130.5 | yes |
| Baseline (X25519 + Ed25519) | payload_10MB.bin | 10,485,760 | 10485760 | 1 | 10,485,790 | 30 (0.0 %) | 15 | 2.1987 | 1.8858 | 4769.1 | 5560.4 | yes |
<!-- /AUTO:payloads -->

### 5.4 Where the time goes

<!-- AUTO:prims -->
| Suite | Operation | Median ms | IQR ms | p95 ms | n |
|---|---|---|---|---|---|
| PQC | ML-KEM-768 KeyGen (ephemeral, Alice) | 0.0761 | 0.0032 | 0.0848 | 200 |
| PQC | ML-KEM-768 Encaps (Bob) | 0.0260 | 0.0002 | 0.0263 | 200 |
| PQC | ML-KEM-768 Decaps (Alice) | 0.0217 | 0.0004 | 0.0235 | 200 |
| PQC | ML-DSA-65 Sign (each side once) | 0.4213 | 0.5078 | 1.4923 | 200 |
| PQC | ML-DSA-65 Verify (each side once) | 0.1196 | 0.0056 | 0.1349 | 200 |
| PQC | HKDF-SHA256 extract + 7 expands | 0.0143 | 0.0001 | 0.0145 | 200 |
| CLASSICAL | X25519 KeyGen (ephemeral, Alice) | 0.0309 | 0.0011 | 0.0332 | 200 |
| CLASSICAL | X25519 Encaps (Bob) | 0.0626 | 0.0025 | 0.0982 | 200 |
| CLASSICAL | X25519 Decaps (Alice) | 0.0331 | 0.0205 | 0.1003 | 200 |
| CLASSICAL | Ed25519 Sign (each side once) | 0.0308 | 0.0084 | 0.0686 | 200 |
| CLASSICAL | Ed25519 Verify (each side once) | 0.0905 | 0.0052 | 0.1327 | 200 |
| CLASSICAL | HKDF-SHA256 extract + 7 expands | 0.0152 | 0.0007 | 0.0201 | 200 |
| HYBRID | X25519+ML-KEM-768 KeyGen (ephemeral, Alice) | 0.1055 | 0.0011 | 0.1121 | 200 |
| HYBRID | X25519+ML-KEM-768 Encaps (Bob) | 0.0848 | 0.0003 | 0.0886 | 200 |
| HYBRID | X25519+ML-KEM-768 Decaps (Alice) | 0.0507 | 0.0001 | 0.0520 | 200 |
| HYBRID | ML-DSA-65 Sign (each side once) | 0.4731 | 0.4467 | 1.2809 | 200 |
| HYBRID | ML-DSA-65 Verify (each side once) | 0.1143 | 0.0002 | 0.1172 | 200 |
| HYBRID | HKDF-SHA256 extract + 7 expands | 0.0143 | 0.0001 | 0.0145 | 200 |
<!-- /AUTO:prims -->

![Primitive costs](results/figures/fig3_primitive_costs.png)

## 6. Comparison with the classical baseline (X25519 + Ed25519)

<!-- AUTO:ratios -->
- **Bytes:** PQC handshake = 9,282 B vs baseline 572 B -> **16.2x** (+8,710 B per handshake; deterministic, identical on every machine).
- **Latency (in-process):** PQC median 1.492 ms vs baseline 0.418 ms -> **3.57x** (+1.074 ms).
- **Latency (TCP loopback):** PQC median 1.506 ms vs baseline 0.444 ms -> **3.39x** (+1.062 ms).
- **Record layer:** identical AES-256-GCM in both suites - 10 MB encrypt median 3.44 ms (PQC) vs 3.23 ms (classical-baseline); PQC changes only the handshake.
<!-- /AUTO:ratios -->

**Explanation:**

* **Bytes.** Nearly all of the extra size is structural, from the standard sizes:
  * **ML-DSA-65 signatures** (2 × 3,309 B = 6,618 B, 71 % of the PQC handshake) cost far more than the KEM.
  * **ML-KEM-768** adds 1,184 B (encapsulation key) + 1,088 B (ciphertext) = 2,272 B, against 64 B for X25519.
  * Framing, identities, nonces, key ids and Finished MACs are almost the same in both suites (≈ 380–390 B).
* **Latency.** The PQC handshake costs a few milliseconds more of CPU (§5.4):
  * **ML-DSA-65 signing** is the slowest single operation. Its time is heavy-tailed because FIPS 204 signing uses rejection sampling, so the number of iterations varies; this explains the wide IQR and p95 of the PQC handshake.
  * ML-KEM-768 itself is as fast as X25519 or faster: Encaps and Decaps are each around 0.05 ms.
* **Record layer.** It is identical in both suites, so the 1 KB / 100 KB / 10 MB payloads cost the same in each. Post-quantum protection adds cost **only at session setup**, not per message.

## 7. Security and performance trade-offs

1. **On fast links, compute dominates. On slow links, bytes dominate.** Platform D (§7.1) shows how the absolute penalty grows as bandwidth falls:
   * The PQC penalty is a few ms on a LAN, which is pure compute, and about +6 ms on 4G (50 ms RTT, 10 Mbit/s), where the round-trip time hides it.
   * At 1 Mbit/s it is about +46 ms.
   * At 100 kbit/s it is about +440 ms. That matches the analytical cost of the extra 5,465 bytes on Alice's critical path (CH + server flight), sent at 100 kbit/s (≈ 437 ms).

   Alice's 3,317 B ClientVerify is not on her own critical path, but it delays the moment Bob can use the session (the "connect → confirmed" column).
2. **No extra round trips.** The largest flight, Bob's SH+SV+SF at 4,593 B (about 4 TCP segments), fits in a standard TCP initial congestion window of 10 segments. PQC therefore adds serialization delay but no extra RTT. Larger flights, such as certificate chains, would cross that limit; see §9.
3. **Mutual authentication doubles the signature cost** (+3.3 kB, one Sign and one Verify). In return it closes the active-downgrade and impersonation gaps that T9 demonstrates. Server-only authentication would save about 36 % of the PQC bytes, but would have to be disclosed as a limitation.
4. **Hybrid** (X25519+ML-KEM-768) costs only +78 B and about 0.1 ms over pure PQC. It hedges against a flaw in the new ML-KEM implementation or analysis while keeping quantum safety.
5. **Platform B** (1 core, single-threaded, 128 MB): B/A ratios are close to 1 apart from noise, because every primitive is single-threaded already (the kit FAQ expects this). Peak memory of the whole process tree stayed well inside the 128 MB budget, including the 10 MB payload; see the evidence line below.

<!-- AUTO:platform_b -->
| Suite | Measurement | OK/trials (B) | A median ms | B median ms | B/A |
|---|---|---|---|---|---|
| PQC (ML-KEM-768 + ML-DSA-65) | inproc | 100/100 | 1.492 | 1.397 | 0.94 |
| PQC (ML-KEM-768 + ML-DSA-65) | loopback | 100/100 | 1.506 | 1.633 | 1.08 |
| Baseline (X25519 + Ed25519) | inproc | 100/100 | 0.418 | 0.419 | 1.00 |
| Baseline (X25519 + Ed25519) | loopback | 100/100 | 0.444 | 0.464 | 1.05 |
| Hybrid ext. (X25519+ML-KEM-768 + ML-DSA-65) | inproc | 100/100 | 1.825 | 1.522 | 0.83 |
| Hybrid ext. (X25519+ML-KEM-768 + ML-DSA-65) | loopback | 100/100 | 1.630 | 1.621 | 0.99 |

Platform B evidence (`platform_runs.jsonl`): `one` status=ok, peak RSS 83.4 MB / 128 MB, not supported; `one` status=ok, peak RSS 97.7 MB / 128 MB, not supported
<!-- /AUTO:platform_b -->

### 7.1 Platform D (optional): emulated network links

This table uses the same workload as Platform A, sent over a user-space link emulator (`src/qsc/netem.py`); see `platform_D.md`. "Model" is RTT + serialization of CH and the server flight + in-process compute.

<!-- AUTO:platform_d -->
| Profile | RTT ms | Mbit/s | Suite | OK/trials | Handshake median ms | IQR ms | Model ms | Connect->confirmed ms | Bytes |
|---|---|---|---|---|---|---|---|---|---|
| lan | 1 | 100 | PQC (ML-KEM-768 + ML-DSA-65) | 15/15 | 4.21 | 0.70 | 2.93 | 6.38 | 9282 |
| lan | 1 | 100 | Baseline (X25519 + Ed25519) | 15/15 | 2.18 | 0.17 | 1.45 | 4.00 | 572 |
| mobile | 50 | 10 | PQC (ML-KEM-768 + ML-DSA-65) | 15/15 | 68.54 | 3.93 | 56.20 | 131.79 | 9282 |
| mobile | 50 | 10 | Baseline (X25519 + Ed25519) | 15/15 | 59.39 | 3.82 | 50.78 | 119.21 | 572 |
| constrained | 100 | 1 | PQC (ML-KEM-768 + ML-DSA-65) | 15/15 | 163.51 | 6.94 | 148.86 | 302.11 | 9282 |
| constrained | 100 | 1 | Baseline (X25519 + Ed25519) | 15/15 | 112.37 | 2.91 | 104.10 | 222.46 | 572 |
| narrowband | 300 | 0.1 | PQC (ML-KEM-768 + ML-DSA-65) | 15/15 | 790.61 | 5.58 | 775.46 | 1376.00 | 9282 |
| narrowband | 300 | 0.1 | Baseline (X25519 + Ed25519) | 15/15 | 346.83 | 2.69 | 337.22 | 671.07 | 572 |

lan: PQC/baseline = 1.93x (+2.0 ms); mobile: PQC/baseline = 1.15x (+9.2 ms); constrained: PQC/baseline = 1.46x (+51.1 ms); narrowband: PQC/baseline = 2.28x (+443.8 ms).
<!-- /AUTO:platform_d -->

![Platform D](results/figures/fig4_platform_D_links.png)

## 8. Limitations (honest)

* **Prototype.** Python, unaudited, with no side-channel hardening beyond what the library provides. Secrets are "wiped" by dropping references, which is best-effort in Python because `bytes` objects are immutable.
* **Trust from pinning only.** There is no PKI, rotation or revocation. Pins must be provisioned out of band; a compromised pin store breaks authentication.
* **No identity hiding.** Names and key ids travel in clear in CH and SH, so a passive observer learns who talks to whom. TLS 1.3 encrypts these.
* **Replay cache** is in memory and bounded at 100k nonces, with no timestamp. A replayed ClientHello after a restart makes Bob spend one Encaps and one Sign, but cannot produce a session (T8).
* **DoS amplification.** Bob signs (ML-DSA, about 1 ms) before authenticating the client. There are no cookies or rate limits.
* **No key update or rekey.** One session must stay below AES-GCM usage limits; TLS 1.3 rekeys after 2^24.5 full-size records. There is no resumption or 0-RTT.
* **Strict in-order records** assume a reliable transport (TCP). A datagram transport would need a replay window.
* **1-RTT semantics.** Alice holds provisional keys until Bob verifies CV and CF. If Bob rejects, his alert closes Alice's session; Bob never accepts data.
* **Platform D emulation** has no packet loss, jitter, TCP/IP header bytes or congestion-window dynamics.
* **Measurement environment.** The numbers above come from the machine recorded in `platform_A_info.json`. Timings vary with the CPU, but byte counts and pass/fail results are deterministic.

## 9. Evidence-based recommendations and next improvements

1. **Deploy hybrid X25519+ML-KEM-768 key exchange first.** It costs +78 B (§5.2) and about 0.1 ms of extra KEM compute (§5.4) over pure PQC, protects against harvest-now-decrypt-later today, and keeps classical security if an ML-KEM implementation bug appears. The suite already exists (`0x0301`) and passes T1–T9.
2. **Optimise signatures, not the KEM.** About 71 % of the PQC bytes and most of the extra CPU are ML-DSA-65 (§5.2, §5.4).
   * ML-DSA-44 (2,420 B signatures) is an option where NIST category 2 is acceptable.
   * KEM-based authentication (KEMTLS-style) where pinned static KEM keys are possible.
   * Keep a single signer for server-only use cases, and disclose it.
3. **Keep flights inside the TCP initial window (about 14.6 kB).** With certificates (an ML-DSA-65 certificate carries 1,952 B of public key and 3,309 B of signature), a two-certificate chain would push Bob's flight past the window and add an RTT. Prefer pinning, certificate compression or KEMTLS on constrained links (Platform D, narrowband profile: +440 ms already).
4. **Production hardening:** encrypt identities under handshake keys; add a stateless cookie (HelloRetry) before the server signs; add a KeyUpdate message; use a persistent or time-windowed replay cache; use a side-channel-reviewed implementation in a memory-safe language such as rustls, BoringSSL or liboqs.
5. **Run on a real link between two machines** with `scripts/channel.py` to cover packet loss and real TCP behaviour, which the emulator does not model.

## 10. Reproducibility statement

```
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt             # cryptography 50.0.2, pqcrypto 1.0.0 (pinned)
python run_all.py                                     # every table + figure (≈2-5 min); --quick ≈1 min
```

Each step can also be run on its own; see README §3. Raw data is in `results/`. Figures are produced by `scripts/make_figures.py` and tables by `scripts/make_report.py`. The machine is recorded in `platform_A_info.json`, and Platform B evidence in `platform_runs.jsonl`. Library versions are listed in `requirements.txt` and recorded in `platform_A_info.json`.
