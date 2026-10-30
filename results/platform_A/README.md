# Platform A Benchmark & Security Test Results

This directory contains the complete set of raw measurement data and test outputs produced on **Platform A** (the primary evaluation environment).

## Platform A Specifications
- **Operating System:** Darwin 27.0.0 (macOS, `arm64` Apple Silicon)
- **CPU:** 8 physical / 8 logical cores @ up to 3.20 GHz
- **RAM:** 8.0 GB Unified Memory
- **Python:** 3.12.13 (CPython)
- **Cryptographic Libraries:** `cryptography` 50.0.2, `pqcrypto` 1.0.0, `psutil` 7.2.2
- **Hardware Record:** `platform_A_info.json`

## Files in this Directory

| File | Description | Trials / Scope |
|---|---|---|
| `platform_A_info.json` | Complete machine hardware and software environment profile | System metadata |
| `handshake_results.csv` | Summary metrics: median, IQR, p95 latencies and byte totals for PQC, Classical, and Hybrid suites | 100 trials per suite x {inproc, loopback} |
| `handshake_trials.csv` | Granular per-trial timings for each individual handshake execution | 600 total individual trials |
| `handshake_bytes.csv` | Wire overhead per flight (CH, SH, SV, SF, CV, CF) dissected by crypto material vs framing | Exact byte accounting |
| `payload_results.csv` | Symmetric record-layer encryption/decryption throughput, timings, and SHA-256 verification (1 KB, 100 KB, 10 MB) | 15–200 trials per payload size |
| `primitive_timings.csv` | Micro-benchmarks of isolated primitives: ML-KEM-768 KeyGen/Encaps/Decaps, ML-DSA-65 Sign/Verify, HKDF-SHA256 | n=200 iterations |
| `security_tests.csv` | High-level summary of mandatory security tests T1–T9 across PQC, Classical, and Hybrid | 185 / 185 sub-cases PASS |
| `security_tests_detailed.csv` | Exhaustive sub-case log including exact error codes and exception messages for every fault injection | 185 detailed sub-cases |

## Key Platform A Findings Summary
- **Handshake Latency (in-process median):** PQC: **1.492 ms** vs Classical: **0.422 ms** (3.54x ratio, +1.07 ms)
- **Handshake Latency (TCP loopback median):** PQC: **1.538 ms** vs Classical: **0.485 ms** (3.17x ratio, +1.05 ms)
- **Handshake Wire Size:** PQC: **9,282 B** vs Classical: **572 B** (16.2x ratio, +8,710 B; 71.3% from ML-DSA-65 signatures)
- **10 MB Bulk Record Layer:** PQC: **3,222 MB/s** vs Classical: **3,217 MB/s** (Identical AES-256-GCM performance; 0% post-quantum data transfer penalty)
- **Security Tests T1–T9:** 100% Pass rate across all 185 fault-injection scenarios.
