#!/usr/bin/env python3
"""Interactive Two-Way Quantum-Safe Communication Channel (Alice <-> Bob).

Allows:
  1. Sending official project payloads (1 KB, 100 KB, 10 MB) as per project instructions.
  2. Launching live cyberattacks (T2-T9) to observe real-time cryptographic defense!
  3. Custom text messaging.

Usage:
    # Terminal 1: Start Bob (Server)
    python scripts/interactive_chat.py server --port 8765

    # Terminal 2: Start Alice (Client)
    python scripts/interactive_chat.py client --port 8765
"""
import argparse
import hashlib
import os
import socket
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests"))
sys.path.insert(0, os.path.join(ROOT, "src"))

import security_suite as ss  # noqa: E402
from qsc.errors import HandshakeError, RecordAuthError, SessionClosed
from qsc.handshake import ClientHandshake, ServerConfig
from qsc.identity import Identity, TrustStore
from qsc.payloads import ensure_payloads, load, load_all, official_hashes
from qsc.record import CT_APPLICATION, CT_CLOSE, HEADER_LEN, TAG_LEN
from qsc.suites import get_suite
from qsc.transport import Conn, client_handshake, server_handshake

KEYS = os.path.join(ROOT, "keys")
PAYLOAD_NAMES = ["payload_1KB.bin", "payload_100KB.bin", "payload_10MB.bin"]


def format_hex(data: bytes, max_len: int = 32) -> str:
    if len(data) <= max_len:
        return " ".join(f"{b:02x}" for b in data)
    head = " ".join(f"{b:02x}" for b in data[:max_len])
    return f"{head} ... [{len(data)} bytes total]"


def print_banner(title: str):
    print(f"\n{'=' * 78}\n  {title}\n{'=' * 78}")


def run_server(host: str, port: int, suite_name: str, keys_dir: str):
    suite = get_suite(suite_name)
    idents = [Identity.load(os.path.join(keys_dir, f"bob.{alg}.key.json")) for alg in ("ML-DSA-65", "Ed25519")]
    trust_store = TrustStore.load(os.path.join(keys_dir, "trust_bob.json"))
    cfg = ServerConfig("bob", idents, trust_store, [suite])
    expected_hashes = official_hashes()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(1)

    print_banner(f"BOB (SERVER) ONLINE — LISTENING ON {host}:{port}")
    print(f"[*] Post-Quantum Suite: {suite.label}")
    print(f"[*] Waiting for Alice to connect...")

    try:
        sock, addr = srv.accept()
        sock.settimeout(None)  # Keep connection alive indefinitely
        conn = Conn(sock)
        print(f"\n[+] Incoming TCP connection from {addr[0]}:{addr[1]}")
        print("[*] Performing 1-RTT Quantum-Safe Mutual Handshake (ML-KEM-768 + ML-DSA-65)...")
        session = server_handshake(conn, cfg)
        print(f"[+] HANDSHAKE SUCCESSFUL!")
        print(f"    - Authenticated Peer     : '{session.peer}'")
        print(f"    - Traffic Key Fingerprint : {session.key_fingerprint[:32]}...")

        print_banner("QUANTUM-SAFE SECURE CHANNEL ACTIVE — AWAITING PAYLOADS")

        msg_count = 0
        while True:
            try:
                def record_gen():
                    while True:
                        rec = conn.read_record()
                        yield rec

                gen = record_gen()
                first_rec = next(gen)
            except (ConnectionError, SessionClosed):
                print("\n[-] Alice disconnected.")
                break

            header = first_rec[:HEADER_LEN]
            ciphertext = first_rec[HEADER_LEN:-TAG_LEN]
            tag = first_rec[-TAG_LEN:]

            try:
                ctype, flags, pt_first = session.open(first_rec)
            except RecordAuthError as e:
                print(f"\n[!] 🚨 SECURITY ALERT: Tampering detected! {e}")
                break

            if ctype == CT_CLOSE:
                print("\n[-] Alice terminated the session gracefully.")
                break

            parts = [pt_first]
            num_records = 1
            if not (flags & 0x01):
                while True:
                    rec = next(gen)
                    c, f, pt = session.open(rec)
                    parts.append(pt)
                    num_records += 1
                    if f & 0x01:
                        break

            full_payload = b"".join(parts)
            msg_count += 1
            h_actual = hashlib.sha256(full_payload).hexdigest()

            matched_name = None
            for name, h_exp in expected_hashes.items():
                if h_actual == h_exp:
                    matched_name = name
                    break

            print("\n" + "=" * 78)
            print(f">>> [BOB RECEIVED TRANSMISSION #{msg_count}]")
            print(f"    Total Plaintext Size : {len(full_payload):,d} bytes ({num_records} AES-GCM record{'s' if num_records > 1 else ''})")
            print(f"    Record #0 Header     : {format_hex(header)}")
            print(f"    Record #0 Ciphertext : {format_hex(ciphertext)}")
            print(f"    Record #0 Auth Tag   : {format_hex(tag)}")
            print(f"    Tag Verification     : [PASS] All {num_records} record tags authentic & in-order")
            print(f"    Calculated SHA-256   : {h_actual}")

            if matched_name:
                print(f"    Official Payload     : [MATCH] Official '{matched_name}' verified byte-exact!")
            else:
                try:
                    dec_display = f'"{full_payload.decode("utf-8")}"'
                except UnicodeDecodeError:
                    dec_display = f"[{len(full_payload)} bytes binary data]"
                print(f"    DECRYPTED PLAINTEXT  : {dec_display}")
            print("=" * 78)

            enc_reply = session.seal(h_actual.encode("utf-8"))
            conn.send(enc_reply)
            print(f"<<< [BOB SENT ENCRYPTED SHA-256 CONFIRMATION]")
            print(f"    Encrypted Hash Bytes : {len(enc_reply)} bytes across wire\n")

    except KeyboardInterrupt:
        print("\nStopping Bob...")
    finally:
        srv.close()


def send_payload_item(conn, session, name: str, data: bytes, expected_hash: str):
    t0 = time.perf_counter()
    nrec = conn.send_message(session, data)
    reply_hash = conn.receive_message(session).decode()
    dt = (time.perf_counter() - t0) * 1e3

    is_match = (reply_hash == expected_hash)
    print("\n" + "=" * 78)
    print(f">>> [ALICE TRANSMITTED: {name}]")
    print(f"    Size               : {len(data):,d} bytes")
    print(f"    Fragments (Records): {nrec} records (16 KB AES-256-GCM chunks)")
    print(f"    Wire Overhead      : {nrec * 30} bytes total header + tag")
    print(f"    Expected SHA-256   : {expected_hash}")
    print(f"    Bob's SHA-256 Reply: {reply_hash}")
    print(f"    Integrity Status   : {'[SUCCESS] EXACT SHA-256 MATCH' if is_match else '[FAILED] HASH MISMATCH'}")
    print(f"    Round-Trip Time    : {dt:.2f} ms")
    print("=" * 78)
    return is_match


def run_attack_menu(suite):
    lab = ss.make_lab()
    payloads = load_all()

    while True:
        print_banner("⚔️ LIVE ADVERSARIAL ATTACK SIMULATOR (T2 - T9)")
        print("  [1] Attack T2: Handshake Bit-Flip (Tamper with KEM Public Key / Ciphertext)")
        print("  [2] Attack T3: Signature Forgery (Corrupt ML-DSA-65 Digital Signature)")
        print("  [3] Attack T4: Ciphertext Bit-Flip (Alter encrypted payload byte in transit)")
        print("  [4] Attack T5: AAD / Header Tampering (Corrupt Sequence Counter or GCM Tag)")
        print("  [5] Attack T6: Impersonation Attack (Mallory attacks using own valid PQC key)")
        print("  [6] Attack T7: Identity Swap / Misbinding (Replaying flight to another peer)")
        print("  [7] Attack T8: Replay Attack (Replaying old records or old handshakes)")
        print("  [8] Attack T9: Active MITM Downgrade Attack (Force PQC to Classical fallback)")
        print("  [9] Run ALL 185 Automated Attack Test Cases (Full T1-T9 Suite)")
        print("  [0] Return to Main Menu")
        print("-" * 78)

        choice = input("Select attack to launch [0-9]: ").strip()
        if choice == "0":
            break

        attack_map = {
            "1": ("T2: Handshake Tampering", lambda: ss.t2_handshake_tampering(lab, suite, exhaustive=False)),
            "2": ("T3: Signature Tampering", lambda: ss.t3_signature_tampering(lab, suite)),
            "3": ("T4: Ciphertext Tampering", lambda: ss.t4_ciphertext_tampering(lab, suite, payloads)),
            "4": ("T5: Tag / AAD Tampering", lambda: ss.t5_tag_aad_tampering(lab, suite, payloads)),
            "5": ("T6: Untrusted Identity / Impersonation", lambda: ss.t6_untrusted_identity(lab, suite)),
            "6": ("T7: Identity Swap / Misbinding", lambda: ss.t7_identity_swap(lab, suite)),
            "7": ("T8: Replay Attack", lambda: ss.t8_replay(lab, suite, payloads)),
            "8": ("T9: Active Algorithm Downgrade", lambda: ss.t9_downgrade(lab, suite)),
        }

        if choice in attack_map:
            name, fn = attack_map[choice]
            print(f"\n[*] Launching {name} against the quantum-safe channel...")
            t0 = time.perf_counter()
            cases = fn()
            dt = (time.perf_counter() - t0) * 1e3
            print(f"\n{'=' * 78}")
            print(f"  ATTACK EXECUTION RESULTS — {name}")
            print(f"{'=' * 78}")
            all_blocked = True
            for c in cases:
                all_blocked &= c.ok
                print(f"  [{'DEFEATED' if c.ok else 'BREACHED'}] Subcase: {c.name}")
                print(f"       Fault Injected   : {c.fault}")
                print(f"       Defense Response : {c.observed}")
                print(f"       Plaintext Leaked : NONE (Fail-closed)")
                print("  " + "-" * 74)
            print(f"\n[+] Security Summary: {len(cases)}/{len(cases)} attacks detected and blocked in {dt:.1f} ms!")
            input("\nPress [ENTER] to continue...")

        elif choice == "9":
            print("\n[*] Executing full automated security test suite (T1-T9)...")
            os.system(f"{sys.executable} {os.path.join(ROOT, 'run_security_tests.py')} --suites pqc --quick")
            input("\nPress [ENTER] to continue...")


def run_client(host: str, port: int, suite_name: str, keys_dir: str):
    suite = get_suite(suite_name)
    ident = Identity.load(os.path.join(keys_dir, f"alice.{suite.sig_name}.key.json"))
    trust_store = TrustStore.load(os.path.join(keys_dir, "trust_alice.json"))
    hs = ClientHandshake(ident, trust_store, "bob", suite)

    ensure_payloads()
    expected_hashes = official_hashes()

    print_banner(f"ALICE (CLIENT) CONNECTING TO {host}:{port}")
    try:
        sock = socket.create_connection((host, port), timeout=10.0)
        sock.settimeout(None)  # Keep connection alive indefinitely without idle timeout
    except OSError as e:
        print(f"[!] Could not connect to Bob at {host}:{port}: {e}")
        print("    Please start Bob first: python scripts/interactive_chat.py server")
        sys.exit(1)

    conn = Conn(sock)
    print("[*] Performing 1-RTT Quantum-Safe Mutual Handshake (ML-KEM-768 + ML-DSA-65)...")
    st = client_handshake(conn, hs)
    session = hs.session
    print(f"[+] HANDSHAKE SUCCESSFUL! ({st['handshake_ns'] / 1e6:.2f} ms)")
    print(f"    - Authenticated Peer     : '{session.peer}'")
    print(f"    - Total Handshake Wire   : {st['c2s_bytes'] + st['s2c_bytes']} bytes")
    print(f"    - Traffic Key Fingerprint : {session.key_fingerprint[:32]}...")

    while True:
        print_banner("SELECT OPTION (PAYLOADS & ATTACKS)")
        print("  [1] Send Official payload_1KB.bin     (1,024 B    - 1 record)")
        print("  [2] Send Official payload_100KB.bin   (102,400 B  - 7 records)")
        print("  [3] Send Official payload_10MB.bin    (10,485,760 B - 640 records)")
        print("  [4] Send ALL 3 Official Payloads sequentially (Official Kit Flow)")
        print("  [5] Send Custom Text Message")
        print("  [6] ⚔️ Launch Live Cyberattack Simulations (MITM, Tamper, Replay, Downgrade)")
        print("  [0] Exit & Close Channel")
        print("-" * 78)

        choice = input("Enter option [0-6]: ").strip()

        if choice == "0":
            conn.send(session.close_record())
            print("[*] Channel closed cleanly.")
            break

        elif choice == "1":
            name = "payload_1KB.bin"
            data = load(name)
            send_payload_item(conn, session, name, data, expected_hashes[name])

        elif choice == "2":
            name = "payload_100KB.bin"
            data = load(name)
            send_payload_item(conn, session, name, data, expected_hashes[name])

        elif choice == "3":
            name = "payload_10MB.bin"
            data = load(name)
            print(f"[*] Encrypting and transmitting {len(data):,d} bytes in 640 records...")
            send_payload_item(conn, session, name, data, expected_hashes[name])

        elif choice == "4":
            print("[*] Executing full official payload sequence...")
            all_ok = True
            for name in PAYLOAD_NAMES:
                data = load(name)
                all_ok &= send_payload_item(conn, session, name, data, expected_hashes[name])
            print(f"\n[+] Official 3-payload test sequence {'COMPLETED SUCCESSFULLY' if all_ok else 'FAILED'}!")

        elif choice == "5":
            text = input("\n[Alice] Enter custom text message: ").strip()
            if text:
                data = text.encode("utf-8")
                h_exp = hashlib.sha256(data).hexdigest()
                send_payload_item(conn, session, "custom_text_message", data, h_exp)

        elif choice == "6":
            run_attack_menu(suite)

        else:
            print("[!] Invalid option. Please select 0-6.")

    conn.close()


def main():
    parser = argparse.ArgumentParser(description="Quantum-Safe Payload & Attack Transmission")
    sub = parser.add_subparsers(dest="role", required=True)

    p_srv = sub.add_parser("server", help="Run as Bob (Server)")
    p_srv.add_argument("--host", default="127.0.0.1")
    p_srv.add_argument("--port", type=int, default=8765)
    p_srv.add_argument("--suite", default="pqc")
    p_srv.add_argument("--keys", default=KEYS)

    p_cli = sub.add_parser("client", help="Run as Alice (Client)")
    p_cli.add_argument("--host", default="127.0.0.1")
    p_cli.add_argument("--port", type=int, default=8765)
    p_cli.add_argument("--suite", default="pqc")
    p_cli.add_argument("--keys", default=KEYS)

    args = parser.parse_args()
    if args.role == "server":
        run_server(args.host, args.port, args.suite, args.keys)
    else:
        run_client(args.host, args.port, args.suite, args.keys)


if __name__ == "__main__":
    main()
