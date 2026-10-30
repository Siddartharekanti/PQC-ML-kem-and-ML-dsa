#!/usr/bin/env python3
"""Alice client for the QSC/1 quantum-safe channel.

This client authenticates Bob against bob.pub.json, establishes ML-KEM/ML-DSA
traffic keys, synchronizes full public-key bundles inside the authenticated
session, and exchanges AES-256-GCM protected messages and files.
"""

import argparse
import hashlib
import os
import queue
import shlex
import socket
import sys
import threading
import time

import qsc_core as qsc


def send_file(conn, session, path, log, sent_hashes):
    size = os.path.getsize(path)
    if size > qsc.MAX_FILE_SIZE:
        raise ValueError(f"file is {size:,} B; maximum supported size is {qsc.MAX_FILE_SIZE:,} B")
    with open(path, "rb") as f:
        data = f.read()
    name = os.path.basename(path)
    digest = hashlib.sha256(data).hexdigest()
    sent_hashes[name] = digest
    log.info(f"sending file '{name}' ({len(data):,} bytes, sha256 {digest})")
    qsc.send_app(conn, session, b"P", qsc.pack_named(name, data), log)
    return name


def send_official_payload(conn, session, name, log, sent_hashes):
    if name not in qsc.PAYLOADS:
        raise ValueError("unknown payload; choose " + ", ".join(qsc.PAYLOADS))
    data = qsc.make_payload(name)
    sent_hashes[name] = hashlib.sha256(data).hexdigest()
    log.info(f"sending official payload '{name}' ({len(data):,} bytes)")
    qsc.send_app(conn, session, b"P", qsc.pack_named(name, data), log)
    return name


def wait_for_receipts(receipts, expected, timeout, log):
    pending = set(expected)
    deadline = time.monotonic() + timeout
    while pending:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            log.warn("timed out waiting for receipts: " + ", ".join(sorted(pending)))
            return False
        try:
            name = receipts.get(timeout=min(remaining, 0.5))
        except queue.Empty:
            continue
        if name is None:
            log.warn("connection closed while waiting for file receipts")
            return False
        pending.discard(name)
    log.ok("all file receipts received")
    return True


def print_chat_help(log):
    log._p("\n  Bidirectional encrypted communication commands:")
    log._p("    <text>                  send text to Bob")
    log._p("    /send <file path>       send a file to Bob")
    log._p("    /payload <name>         send a generated official payload")
    log._p("    /help                   show these commands")
    log._p("    /quit                   close the connection")


def interactive_chat(conn, session, log, sent_hashes):
    print_chat_help(log)
    lines = qsc.stdin_lines()
    while not session.closed:
        try:
            line = lines.get(timeout=0.3)
        except queue.Empty:
            continue
        if line is None or line.strip() == "/quit":
            return
        if not line.strip():
            continue
        try:
            words = shlex.split(line)
            if words[0] in ("/send", "/file"):
                if len(words) != 2:
                    raise ValueError("usage: /send <file path>")
                send_file(conn, session, words[1], log, sent_hashes)
            elif words[0] == "/payload":
                if len(words) != 2:
                    raise ValueError("usage: /payload <name>")
                send_official_payload(conn, session, words[1], log, sent_hashes)
            elif words[0] == "/help":
                print_chat_help(log)
            elif words[0].startswith("/"):
                raise ValueError(f"unknown command '{words[0]}'; use /help")
            else:
                qsc.send_app(conn, session, b"T", line.encode(), log)
        except (OSError, qsc.QSCError) as e:
            log.bad(str(e))
            if session.closed:
                return
        except (ValueError, UnicodeError) as e:
            log.bad(str(e))


def close_securely(conn, session):
    if session.closed:
        return
    try:
        with session.lock:
            conn.send(session.seal(b"", ctype=qsc.CT_CLOSE))
    except (OSError, qsc.QSCError):
        pass
    session.closed = True


def parse_args():
    ap = argparse.ArgumentParser(description="COMPUTER 1 - Alice, quantum-safe QSC/1 client")
    ap.add_argument("host", nargs="?", default="127.0.0.1",
                    help="Bob's IP address or hostname (default: 127.0.0.1)")
    ap.add_argument("--port", type=int, default=5002, help="Bob's TCP port (default: 5002)")
    ap.add_argument("--init", action="store_true",
                    help="create alice.key.json and alice.pub.json, then exit")
    ap.add_argument("--name", default="alice", help="my identity name (default: alice)")
    ap.add_argument("--key", help="my private key file (default: <name>.key.json)")
    ap.add_argument("--server-name", default="bob", help="expected server identity (default: bob)")
    ap.add_argument("--server-pub", default="bob.pub.json",
                    help="Bob's pinned public-key file (default: bob.pub.json)")
    ap.add_argument("--suite", choices=("pqc", "classical"), default="pqc")
    ap.add_argument("--chat", action="store_true", help="open interactive encrypted chat")
    ap.add_argument("--message", action="append", default=[], help="send a text message (repeatable)")
    ap.add_argument("--send", action="append", default=[], metavar="FILE",
                    help="send a file (repeatable)")
    ap.add_argument("--demo", action="store_true",
                    help="send a test message and all three official payloads")
    ap.add_argument("--runs", type=int, default=0, metavar="N",
                    help="complete N successful bidirectional official-payload sessions; retry attacks/faults")
    ap.add_argument("--attack-csv", default="results/attack_events.csv", metavar="FILE",
                    help="append detected attack/fault data here (default: results/attack_events.csv)")
    ap.add_argument("--retry-delay", type=float, default=1.0, metavar="SECONDS",
                    help="delay before reconnecting after an interrupted automated run (default: 1.0)")
    ap.add_argument("--receive-dir", default="received", metavar="DIR",
                    help="directory for files received from Bob (default: received)")
    ap.add_argument("--timeout", type=float, default=15.0, help="connect timeout in seconds")
    ap.add_argument("--hide-secrets", action="store_true")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()
    if args.runs < 0:
        ap.error("--runs must be zero (normal mode) or a positive integer")
    if args.retry_delay < 0:
        ap.error("--retry-delay cannot be negative")
    if args.runs and (args.chat or args.message or args.send or args.demo):
        ap.error("--runs cannot be combined with --chat, --message, --send, or --demo")
    return args


def run_automated_sessions(a, my_name, my_ids, server_pins, suite, log):
    """Keep reconnecting until N complete, verified bidirectional runs succeed."""
    successful_runs = 0
    attempts = 0
    while successful_runs < a.runs:
        attempts += 1
        phase = "connect"
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(a.timeout)
        conn = None
        session = None
        try:
            log.banner(f"AUTOMATED ATTEMPT {attempts}: {successful_runs}/{a.runs} successful")
            sock.connect((a.host, a.port))
            sock.settimeout(None)
            conn = qsc.Conn(sock)
            phase = "handshake"
            session = qsc.client_handshake(
                conn, my_name, my_ids, a.server_name, server_pins, suite, log,
            )
            phase = "key-exchange"
            qsc.client_secure_public_key_exchange(
                conn, session, my_name, my_ids, a.server_name, server_pins, log,
            )
            qsc.established_banner(log, session, "Bob, server")
            phase = "payload-exchange"
            qsc.exchange_official_payloads(conn, session, log, client_first=True)
            successful_runs += 1
            log.banner(
                f"AUTOMATED RUN {successful_runs}/{a.runs} PASS: all payloads verified both ways", "1;32"
            )
        except (qsc.QSCError, ConnectionError, OSError, UnicodeError) as e:
            if qsc.is_security_attack(e):
                qsc.attack_detected(log, e)
            else:
                log.warn(f"session fault/configuration mismatch during {phase} (not classified as attack): {e}")
            qsc.save_attack_csv(
                a.attack_csv, "alice/client", phase, e, f"{a.host}:{a.port}", attempts, successful_runs,
            )
            log.info(f"attack/fault recorded in {a.attack_csv}; restarting with a fresh session")
        finally:
            if conn is not None and session is not None:
                close_securely(conn, session)
                conn.close()
            else:
                sock.close()
        if successful_runs < a.runs and phase != "payload-exchange":
            time.sleep(a.retry_delay)
    return 0


def main():
    a = parse_args()
    qsc.SHOW_SECRETS = not a.hide_secrets
    qsc.USE_COLOR = qsc.USE_COLOR and not a.no_color
    log = qsc.Log("ALICE", "36")

    if a.init:
        key_path, pub_path = qsc.init_identity(a.name)
        _, identities = qsc.load_identity(key_path)
        log.banner(f"Created identity '{a.name}'")
        log._p(f"  private key file : {key_path}   <- KEEP SECRET on Alice's computer")
        log._p(f"  public key file  : {pub_path}   <- optional pin for Bob")
        for alg, (_, public_key) in identities.items():
            log._p(f"  {alg:10s} key id: {qsc.key_id(public_key).hex()}")
        return 0

    try:
        my_name, my_ids = qsc.load_identity(a.key or f"{a.name}.key.json")
        server_name_in_file, server_pins = qsc.load_pub(a.server_pub)
    except (OSError, ValueError, KeyError, qsc.QSCError) as e:
        log.bad(f"could not load identity keys: {e}")
        return 2

    if server_name_in_file != a.server_name:
        log.bad(f"{a.server_pub} belongs to '{server_name_in_file}', not expected server '{a.server_name}'")
        return 2

    suite = qsc.BY_NAME[a.suite]
    log.banner(f"ALICE connecting to {a.host}:{a.port}")
    log.kv("my identity", f"'{my_name}' ({suite.sig} key id {qsc.key_id(my_ids[suite.sig][1]).hex()})")
    log.kv("expected server", f"'{a.server_name}' pinned by {a.server_pub}")
    log.kv("suite", f"{suite.label} ({suite.alg_string})")

    if a.runs:
        try:
            return run_automated_sessions(a, my_name, my_ids, server_pins, suite, log)
        except KeyboardInterrupt:
            log.info("automated runs stopped by user")
            return 130

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(a.timeout)
    try:
        sock.connect((a.host, a.port))
        sock.settimeout(None)
        conn = qsc.Conn(sock)
        session = qsc.client_handshake(conn, my_name, my_ids, a.server_name, server_pins, suite, log)
        qsc.client_secure_public_key_exchange(
            conn, session, my_name, my_ids, a.server_name, server_pins, log,
        )
    except qsc.HandshakeError as e:
        qsc.attack_detected(log, e)
        sock.close()
        return 1
    except qsc.QSCError as e:
        qsc.attack_detected(log, e)
        sock.close()
        return 1
    except (ConnectionError, OSError) as e:
        log.bad(f"could not connect to Bob at {a.host}:{a.port}: {e}")
        sock.close()
        return 1

    qsc.established_banner(log, session, "Bob, server")
    receipts = queue.Queue()
    sent_hashes = {}
    receiver = threading.Thread(target=qsc.rx_loop,
                                args=(conn, session, log, "Alice", receipts, False,
                                      sent_hashes, a.receive_dir), daemon=True)
    receiver.start()

    expected_receipts = []
    try:
        for message in a.message:
            qsc.send_app(conn, session, b"T", message.encode(), log)
        for path in a.send:
            expected_receipts.append(send_file(conn, session, path, log, sent_hashes))
        if a.demo:
            qsc.send_app(conn, session, b"T", b"Hello Bob - quantum-safe channel established!", log)
            for name in qsc.PAYLOADS:
                expected_receipts.append(send_official_payload(conn, session, name, log, sent_hashes))

        if expected_receipts:
            wait_for_receipts(receipts, expected_receipts, max(120.0, a.timeout), log)

        batch_requested = bool(a.message or a.send or a.demo)
        if a.chat or not batch_requested:
            interactive_chat(conn, session, log, sent_hashes)
        elif a.message:
            time.sleep(1.0)  # allow Bob's automatic text response to arrive
    except KeyboardInterrupt:
        pass
    except (OSError, qsc.QSCError) as e:
        log.bad(str(e))
        return 1
    finally:
        close_securely(conn, session)
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
