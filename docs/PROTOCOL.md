# QSC/1 — protocol specification (PS-P1 prototype)

Research prototype. Not a claim of production security.

## 1. Roles, identities and trust model

| Item | Choice |
|---|---|
| Roles | **Alice = client / initiator**, **Bob = server / responder**. |
| Authentication | **Mutual.** Both parties sign the transcript with a long-term identity key. |
| Identity keys | ML-DSA-65 (FIPS 204), with Ed25519 for the classical baseline. Generated at provisioning time and never part of the measured handshake. |
| Trust anchor | **Pinned public keys.** Each endpoint holds a trust store `(identity name, signature algorithm) → public key`, installed out of band (`scripts/channel.py provision` prints SHA-256 key ids so operators can compare them). There is no PKI. |
| Key distribution assumption | The pins are distributed over an authenticated channel before first use, for example at device provisioning or by an administrator. An attacker can read pins (they are public) but cannot change them. |
| What is *never* trusted | Any key, key id or name that arrives on the wire. The wire carries only a 32-byte key id (SHA-256 of the public key) so the receiver can fail early with a clear error. Signatures are always verified with the **locally pinned** key. |
| Ephemeral keys | A fresh ML-KEM-768 key pair per handshake (X25519 for the baseline). This gives forward secrecy: if a long-term ML-DSA key leaks later, past traffic stays protected. |

## 2. Cipher suites (exact parameter sets)

| ID | Label | KEM | Signature | KDF | AEAD |
|---|---|---|---|---|---|
| `0x0101` | **PQC** (required) | ML-KEM-768 (FIPS 203) | ML-DSA-65 (FIPS 204, pure, context string) | HKDF-SHA256 (RFC 5869) | AES-256-GCM (SP 800-38D), 96-bit nonce, 128-bit tag |
| `0x0201` | **CLASSICAL** (baseline) | X25519 (RFC 7748) used as a KEM | Ed25519 (RFC 8032) | HKDF-SHA256 | AES-256-GCM |
| `0x0301` | HYBRID (extension) | X25519 ‖ ML-KEM-768, `ss = ss_mlkem ‖ ss_x25519` | ML-DSA-65 | HKDF-SHA256 | AES-256-GCM |

The library is `cryptography 50.0.2` (OpenSSL / BoringSSL-based Rust bindings). No primitive is implemented in this repository. Sizes on the wire: ML-KEM-768 ek 1184 B, ct 1088 B, ss 32 B. ML-DSA-65 pk 1952 B (never sent), signature 3309 B. X25519 32 B. Ed25519 signature 64 B.

The algorithm identifiers are sent as a suite ID and also as the exact string `"ML-KEM-768,ML-DSA-65,HKDF-SHA256,AES-256-GCM"`. Both are in the signed transcript, and both must match the receiver's policy.

## 3. Message flow (1 round trip)

```
Alice (client)                                                        Bob (server)
  ek_A, dk_A <- KEM.KeyGen()          nonce_A <- 32 random bytes
  CH = ClientHello(version=1, suite, alg_ids, id_A="alice", kid_A,
                   id_B="bob" (intended peer), nonce_A, ek_A)  ------->
                                         check: version, suite in policy, alg_ids == suite,
                                                id_B == me, pin(id_A) and kid_A match, |ek_A|,
                                                nonce_A not in replay cache
                                         (ss, ct) <- KEM.Encaps(ek_A);  nonce_B <- 32 random bytes
                     <-------  SH = ServerHello(version, suite, alg_ids, id_B, kid_B, id_A, nonce_B, ct)
                     <-------  SV = ServerVerify( ML-DSA.Sign(sk_B, TH(CH,SH), ctx="QFF26-P1/v1 server-verify") )
                     <-------  SF = ServerFinished( HMAC-SHA256(s_fin_key, TH(CH..SV)) )
  check: suite/alg_ids == offered, id_B == intended peer, id_A echo == me,
         pin(id_B) and kid_B match;  ss <- KEM.Decaps(dk_A, ct);  verify SV with pinned pk_B;  verify SF
  CV = ClientVerify( ML-DSA.Sign(sk_A, TH(CH..SF), ctx="QFF26-P1/v1 client-verify") )  ------->
  CF = ClientFinished( HMAC-SHA256(c_fin_key, TH(CH..CV)) )                            ------->
                                         verify CV with pinned pk_A;  verify CF
  [traffic keys from TH(CH..CF)]                                  [traffic keys from TH(CH..CF)]
  ==================== AES-256-GCM records, separate key + IV per direction ====================
```

`TH(x..y)` is SHA-256 over the exact serialized bytes of every handshake message from x to y.

**What is authenticated.** Bob's signature covers `TH(CH, SH)`. This includes both identities, both key ids, both nonces, the protocol version, the suite ID and algorithm strings, Alice's ephemeral KEM public key and Bob's KEM ciphertext. Alice's signature covers `TH(CH..SF)`: all of that plus Bob's signature and Finished. The two Finished MACs confirm in both directions that each side holds the same KEM shared secret. The traffic keys are derived from the hash of the complete transcript.

**Domain separation.** The two roles use different FIPS 204 context strings. A signature made in the server role can never verify in the client role (test T7). For Ed25519, which has no context input, the context is length-prefixed onto the message instead.

**Fail-closed.** Any failed check raises an error, moves the state machine to `FAILED` and drops all secrets. A `Session` object, and with it the traffic keys, exists only after the last check passes. Bob sends an abort alert (`0xFF`) and closes the connection. Because the handshake is 1-RTT (as in TLS 1.3), Alice derives her keys before Bob has checked CV and CF. If Bob rejects them, his alert tears down Alice's provisional session, and Bob never accepts a record.

## 4. Wire encoding (canonical, strict)

```
message := type (1) || body_len (4, BE) || field*          types: CH=1 SH=2 SV=3 SF=4 CV=5 CF=6, alert=0xFF
field   := field_id (1) || len (2, BE) || value
```

Each message type has a fixed field order. Fixed-length fields (version, suite, key ids, nonces, Finished) are checked for exact length. Suite-dependent lengths (ek, ct, signature) are checked after the suite is known. Unknown fields, missing fields, reordered fields and trailing bytes all raise `DecodeError`. Every message therefore has exactly one valid encoding, so the transcript hash is well defined.

## 5. Key schedule (HKDF-SHA256)

```
PRK        = HKDF-Extract(salt = nonce_A || nonce_B, IKM = ss)
info(l, h) = "QFF26-P1/v1" || suite_id(2) || len(l) || l || h
s_fin_key  = HKDF-Expand(PRK, info("s finished", TH(CH,SH)), 32)
c_fin_key  = HKDF-Expand(PRK, info("c finished", TH(CH,SH)), 32)
c2s_key/iv = HKDF-Expand(PRK, info("c2s key"/"c2s iv", TH(CH..CF)), 32 / 12)
s2c_key/iv = HKDF-Expand(PRK, info("s2c key"/"s2c iv", TH(CH..CF)), 32 / 12)
exporter   = HKDF-Expand(PRK, info("exporter", TH(CH..CF)), 32)      session id / channel binding
```

## 6. Record layer (AES-256-GCM)

```
record := content_type (1) || flags (1) || seq (8) || length (4)  ||  ciphertext || tag (16)
          \___________________ 14-byte header = AAD ____________/
nonce  := iv_dir XOR (0^32 || seq)         derived, never transmitted (as in TLS 1.3)
```

* `seq` starts at 0 for each direction and increases by 1 per record, so a (key, nonce) pair is never reused.
* The receiver builds the nonce from its **own** expected counter and authenticates the header as received:
  * A `seq` that was already consumed is rejected before decryption (`ReplayError`).
  * Reordered or dropped records, and any change to the header or ciphertext, fail authentication (`InvalidTag`).
  * A record reflected back to its sender, or replayed into another session, fails because the key is different.
* Messages are split into 16 KiB records (`flags` bit 0 marks the final fragment). A message is released to the application only after every one of its fragments has authenticated.
* Overhead per record: 14 B header + 16 B tag = **30 B**. The nonce adds 0 B on the wire.
* Any error closes the session (fail-closed).

## 7. Threat model

Dolev–Yao network attacker: reads, drops, injects, replays, reorders and modifies every byte. The attacker holds valid keys of its own ("mallory") and knows every public key. It may also persuade honest parties to talk to other trusted peers ("charlie", "carol"). Out of scope: compromise of an endpoint or its long-term keys while a session is running, side channels in the host, and denial of service.

| Threat | Mitigation | Test |
|---|---|---|
| MITM key substitution | KEM key and ciphertext bound into both signatures; pinned verification keys | T2, T6 |
| Impersonating Bob or Alice | Pinned trust anchor; mutual signatures | T6 |
| Unknown-key-share / misbinding / role swap | Both identities in CH and SH; checked against the intended peer; role-specific signature contexts | T7 |
| Replay of records | Strict per-direction sequence numbers; nonce bound to the expected sequence number | T8 |
| Replay of handshakes | Fresh nonces and KEM keys on both sides; server ClientHello-nonce cache | T8 |
| Downgrade (suite, algorithms, version) | Strict policy; suite echo check; algorithm IDs in the signed transcript; mutual authentication | T9 |
| Tampering with ciphertext, tag or header | AES-256-GCM with the header as AAD; fail-closed | T4, T5 |
| Harvest now, decrypt later | ML-KEM-768 ephemeral key establishment | design |
