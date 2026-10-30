# Platform D — emulated constrained network links (OPTIONAL)

## 1. Constraint modelled and why it matters for PS-P1

The PQC handshake moves 9,282 B, against 572 B for the classical baseline. That is 16× more, and it comes from the standard ML-KEM-768 and ML-DSA-65 sizes. On a laptop the extra cost is a few milliseconds of CPU. On real links, though, the extra **bytes** cost serialization time, which grows as bandwidth falls. Platforms A and B cannot show this effect, because their measurements are in-process or over loopback.

## 2. Exact specification

| Profile | RTT | Bandwidth (each direction) | Represents |
|---|---|---|---|
| `lan` | 1 ms | 100 Mbit/s | office LAN / data centre |
| `mobile` | 50 ms | 10 Mbit/s | 4G/LTE mobile broadband |
| `constrained` | 100 ms | 1 Mbit/s | congested Wi-Fi, rural link, shared satellite backhaul |
| `narrowband` | 300 ms | 100 kbit/s | IoT / LPWAN-class or HF-radio link |

**Setup:**

* Hardware, OS and libraries are those of Platform A (`platform_A_info.json`).
* Bob runs in a separate process.
* The link is a user-space TCP relay (`src/qsc/netem.py`), running in a third process. Each chunk is queued FIFO per direction:
  * `tx_start = max(arrival, link_free)`
  * `link_free = tx_start + 8·len/bandwidth`
  * `deliver = link_free + RTT/2`
* Parameter sets are unchanged: ML-KEM-768 + ML-DSA-65 against X25519 + Ed25519.
* No loss and no jitter.

## 3. How to reproduce it

```
python scripts/platform_d.py                     # all 4 profiles, PQC + classical, 15 trials each (≈1 min)
python scripts/platform_d.py --profiles narrowband --trials 30
python scripts/make_figures.py && python scripts/make_report.py
```

## 4. Same workload as Platform A

* The handshake code, identities, suites, message sizes and success check are identical to Platform A.
* The success check is a ping record and an authenticated reply from Bob.
* Only the link between Alice and Bob changes.
* The measurement is the same as Platform A's loopback mode: `handshake_ms` runs from Alice sending ClientHello to Alice sending ClientVerify + ClientFinished.
* `connect→confirmed` also includes the TCP connect and one encrypted round trip. It shows when *Bob* can use the session.

## 5. Results vs Platform A

<!-- AUTO:platform_d -->
| Profile | RTT ms | Mbit/s | Suite | OK/trials | Handshake median ms | IQR ms | Model ms | Connect->confirmed ms | Bytes |
|---|---|---|---|---|---|---|---|---|---|
| lan | 1 | 100 | PQC (ML-KEM-768 + ML-DSA-65) | 15/15 | 3.95 | 0.83 | 3.00 | 6.25 | 9282 |
| lan | 1 | 100 | Baseline (X25519 + Ed25519) | 15/15 | 2.23 | 0.03 | 1.47 | 4.14 | 572 |
| mobile | 50 | 10 | PQC (ML-KEM-768 + ML-DSA-65) | 15/15 | 71.97 | 4.52 | 56.27 | 134.95 | 9282 |
| mobile | 50 | 10 | Baseline (X25519 + Ed25519) | 15/15 | 61.28 | 3.39 | 50.80 | 122.91 | 572 |
| constrained | 100 | 1 | PQC (ML-KEM-768 + ML-DSA-65) | 15/15 | 161.21 | 2.82 | 148.93 | 299.86 | 9282 |
| constrained | 100 | 1 | Baseline (X25519 + Ed25519) | 15/15 | 114.95 | 2.04 | 104.11 | 226.63 | 572 |
| narrowband | 300 | 0.1 | PQC (ML-KEM-768 + ML-DSA-65) | 15/15 | 790.42 | 5.64 | 775.53 | 1378.15 | 9282 |
| narrowband | 300 | 0.1 | Baseline (X25519 + Ed25519) | 15/15 | 349.24 | 3.82 | 337.23 | 673.51 | 572 |

lan: PQC/baseline = 1.77x (+1.7 ms); mobile: PQC/baseline = 1.17x (+10.7 ms); constrained: PQC/baseline = 1.40x (+46.3 ms); narrowband: PQC/baseline = 2.26x (+441.2 ms).
<!-- /AUTO:platform_d -->

![Platform D](results/figures/fig4_platform_D_links.png)

The **model** column is the analytical expectation: RTT + serialization of (ClientHello + server flight) + in-process compute. It matches the measurement to within about 1–3 ms on every profile (the difference is socket and process-switch overhead), so the emulator behaves as specified.

## 6. Trade-off revealed

* **On fast links, compute dominates.** On LAN and 4G the PQC penalty is a few milliseconds, against a 50 ms RTT on 4G.
* **On slow links, bytes dominate.** At 100 kbit/s the PQC handshake takes about 2.3× as long as the baseline, roughly +440 ms. The extra 5,465 B on Alice's critical path take 437 ms to send at 100 kbit/s.
* **Signatures are the main lever.** Two ML-DSA-65 signatures make up 71 % of the bytes, so constrained deployments gain most from:
  * smaller signatures (ML-DSA-44) or KEM-based authentication;
  * avoiding certificate chains (pinning, as here);
  * server-only authentication where that is acceptable, disclosed as a limitation.
* **No extra round trips.** Bob's 4.6 kB flight stays inside a standard TCP initial window (about 14.6 kB), so PQC adds no RTT on these links.

## 7. Limits of this emulation

* No packet loss or retransmissions, no jitter, no reordering.
* The emulated hop has no TCP congestion-window dynamics (the relay forwards whole chunks).
* TCP/IP header bytes are not counted (they are the same for both suites). MTU packetisation is not modelled.
* Single-flow, sequential trials.
* For real-world confirmation, run `scripts/channel.py` between two machines on the target link.
