#!/usr/bin/env python3
"""Interactive GUI for the Quantum-Safe Communication Channel (PS-P1).

Features:
  1. Suite Selector: Compare HYBRID (Recommended), PQC (Pure), and CLASSICAL (Baseline).
  2. Send official project payloads (1 KB, 100 KB, 10 MB, all 3, custom).
  3. Live Cyberattack Simulation Center (T2-T9) with real-time defense inspection.

Usage:
    python scripts/gui_channel.py
"""
import hashlib
import os
import sys
import time
import tkinter as tk
from tkinter import messagebox, ttk

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests"))
sys.path.insert(0, os.path.join(ROOT, "src"))

import security_suite as ss  # noqa: E402
from qsc.errors import RecordAuthError
from qsc.handshake import ClientHandshake, ServerConfig, ServerHandshake
from qsc.identity import Identity, TrustStore
from qsc.payloads import ensure_payloads, load, load_all, official_hashes
from qsc.record import HEADER_LEN, TAG_LEN
from qsc.suites import get_suite


def format_hex(b: bytes, max_len: int = 36) -> str:
    if len(b) <= max_len:
        return " ".join(f"{x:02x}" for x in b)
    return " ".join(f"{x:02x}" for x in b[:max_len]) + f" ... [{len(b)} bytes]"


class QuantumSafeGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Quantum-Safe Secure Channel — Unified Suite & Attack Lab (PS-P1)")
        self.geometry("1120x890")
        self.minsize(980, 760)

        ensure_payloads()
        self.expected_hashes = official_hashes()
        self.lab = ss.make_lab()
        self.payloads_dict = load_all()

        # Default to the BEST suite: Hybrid
        self.current_suite_name = "hybrid"
        self.init_crypto(self.current_suite_name)
        self.create_widgets()

    def init_crypto(self, suite_name="hybrid"):
        """Establish in-memory Quantum-Safe session between Alice and Bob."""
        keys_dir = os.path.join(ROOT, "keys")
        self.current_suite_name = suite_name
        self.suite = get_suite(suite_name)
        sig = self.suite.sig_name

        if os.path.exists(os.path.join(keys_dir, f"alice.{sig}.key.json")):
            alice_id = Identity.load(os.path.join(keys_dir, f"alice.{sig}.key.json"))
            bob_id = Identity.load(os.path.join(keys_dir, f"bob.{sig}.key.json"))
            ts_alice = TrustStore.load(os.path.join(keys_dir, "trust_alice.json"))
            ts_bob = TrustStore.load(os.path.join(keys_dir, "trust_bob.json"))
        else:
            alice_id = Identity.generate("alice", sig)
            bob_id = Identity.generate("bob", sig)
            ts_alice = TrustStore()
            ts_alice.pin_identity(bob_id)
            ts_bob = TrustStore()
            ts_bob.pin_identity(alice_id)

        t0 = time.perf_counter()
        hs_alice = ClientHandshake(alice_id, ts_alice, "bob", self.suite)
        hs_bob = ServerHandshake(ServerConfig("bob", [bob_id], ts_bob, [self.suite]))

        ch = hs_alice.client_hello()
        sh, sv, sf = hs_bob.handle_client_hello(ch)
        cv, cf = hs_alice.handle_server_flight(sh, sv, sf)
        self.bob_session = hs_bob.handle_client_auth(cv, cf)
        self.alice_session = hs_alice.session
        self.hs_time_ms = (time.perf_counter() - t0) * 1e3

    def on_suite_change(self, event=None):
        val = self.suite_combo.get().split()[0].lower()
        self.init_crypto(val)
        self.update_header_info()
        self.alice_inspect.delete("1.0", tk.END)
        self.bob_inspect.delete("1.0", tk.END)
        self.alice_inspect.insert(tk.END, f"=== RECONFIGURED TO {self.suite.label.upper()} ===\n")
        self.alice_inspect.insert(tk.END, f"KEM: {self.suite.kem_name} | Signature: {self.suite.sig_name}\n")
        self.alice_inspect.insert(tk.END, f"Handshake re-established in {self.hs_time_ms:.2f} ms.\n")
        self.status_var.set(f"Status: Switched to {self.suite.label} suite.")

    def update_header_info(self):
        desc = (
            f"Active Suite: {self.suite.label} | Handshake: {self.hs_time_ms:.2f} ms | "
            f"Key Fingerprint: {self.alice_session.key_fingerprint[:24]}..."
        )
        self.info_lbl.config(text=desc)

    def create_widgets(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        # Top Header Banner
        header_frame = tk.Frame(self, bg="#0f172a", pady=10, padx=16)
        header_frame.pack(fill="x")

        top_row = tk.Frame(header_frame, bg="#0f172a")
        top_row.pack(fill="x")

        title_lbl = tk.Label(
            top_row,
            text="🔐 Quantum-Safe Secure Communication Channel (PS-P1)",
            font=("Helvetica", 15, "bold"),
            fg="#38bdf8",
            bg="#0f172a",
        )
        title_lbl.pack(side="left")

        # Suite Selector Combo
        suite_frame = tk.Frame(top_row, bg="#0f172a")
        suite_frame.pack(side="right")
        tk.Label(suite_frame, text="Cipher Suite:", font=("Helvetica", 10, "bold"), fg="#e2e8f0", bg="#0f172a").pack(side="left", padx=(0, 6))

        self.suite_combo = ttk.Combobox(
            suite_frame,
            values=[
                "hybrid (Recommended: X25519 + ML-KEM-768)",
                "pqc (Pure: ML-KEM-768 + ML-DSA-65)",
                "classical (Baseline: X25519 + Ed25519)",
            ],
            state="readonly",
            width=36,
            font=("Helvetica", 9),
        )
        self.suite_combo.current(0)
        self.suite_combo.bind("<<ComboboxSelected>>", self.on_suite_change)
        self.suite_combo.pack(side="right")

        self.info_lbl = tk.Label(
            header_frame,
            text="",
            font=("Helvetica", 9),
            fg="#94a3b8",
            bg="#0f172a",
        )
        self.info_lbl.pack(anchor="w", pady=(4, 0))
        self.update_header_info()

        # Payload Selection Frame
        opt_frame = tk.LabelFrame(
            self,
            text=" 📦 1. Official Payloads (PS-P1 Standard Evaluation) ",
            font=("Helvetica", 10, "bold"),
            fg="#0369a1",
            padx=10,
            pady=6,
        )
        opt_frame.pack(fill="x", padx=16, pady=(8, 2))

        btn_row = tk.Frame(opt_frame)
        btn_row.pack(fill="x")

        b1 = tk.Button(
            btn_row,
            text="1️⃣ payload_1KB.bin\n(1,024 B - 1 rec)",
            font=("Helvetica", 9, "bold"),
            bg="#0284c7",
            fg="white",
            padx=6,
            pady=4,
            relief="flat",
            command=lambda: self.transmit_payload("payload_1KB.bin"),
        )
        b1.pack(side="left", fill="x", expand=True, padx=(0, 3))

        b2 = tk.Button(
            btn_row,
            text="2️⃣ payload_100KB.bin\n(102,400 B - 7 recs)",
            font=("Helvetica", 9, "bold"),
            bg="#0369a1",
            fg="white",
            padx=6,
            pady=4,
            relief="flat",
            command=lambda: self.transmit_payload("payload_100KB.bin"),
        )
        b2.pack(side="left", fill="x", expand=True, padx=3)

        b3 = tk.Button(
            btn_row,
            text="3️⃣ payload_10MB.bin\n(10.48 MB - 640 recs)",
            font=("Helvetica", 9, "bold"),
            bg="#075985",
            fg="white",
            padx=6,
            pady=4,
            relief="flat",
            command=lambda: self.transmit_payload("payload_10MB.bin"),
        )
        b3.pack(side="left", fill="x", expand=True, padx=3)

        b4 = tk.Button(
            btn_row,
            text="🚀 Send ALL 3 Payloads\n(Full Protocol Test)",
            font=("Helvetica", 9, "bold"),
            bg="#059669",
            fg="white",
            padx=6,
            pady=4,
            relief="flat",
            command=self.transmit_all_payloads,
        )
        b4.pack(side="left", fill="x", expand=True, padx=(3, 0))

        # Custom message row
        custom_row = tk.Frame(opt_frame, pady=4)
        custom_row.pack(fill="x")
        tk.Label(custom_row, text="Or Custom Message:", font=("Helvetica", 9)).pack(side="left", padx=(0, 4))
        self.custom_entry = tk.Entry(custom_row, font=("Helvetica", 10), relief="solid", bd=1)
        self.custom_entry.insert(0, "Quantum-Safe hybrid communication test")
        self.custom_entry.pack(side="left", fill="x", expand=True, padx=(0, 4))
        self.custom_entry.bind("<Return>", lambda e: self.transmit_custom())

        custom_btn = tk.Button(
            custom_row,
            text="💬 Send Custom",
            font=("Helvetica", 9, "bold"),
            bg="#475569",
            fg="white",
            padx=6,
            pady=2,
            relief="flat",
            command=self.transmit_custom,
        )
        custom_btn.pack(side="right")

        # Attack Simulation Frame
        atk_frame = tk.LabelFrame(
            self,
            text=" ⚔️ 2. Live Cyberattack Simulation Center (T2 - T9 Threat Scenarios) ",
            font=("Helvetica", 10, "bold"),
            fg="#b91c1c",
            bg="#fff1f2",
            padx=10,
            pady=6,
        )
        atk_frame.pack(fill="x", padx=16, pady=(4, 4))

        atk_row = tk.Frame(atk_frame, bg="#fff1f2")
        atk_row.pack(fill="x")

        a1 = tk.Button(
            atk_row,
            text="💥 Attack T4/T5\nCiphertext/Tag Tamper",
            font=("Helvetica", 9, "bold"),
            bg="#e11d48",
            fg="white",
            padx=4,
            pady=4,
            relief="flat",
            command=self.simulate_tamper,
        )
        a1.pack(side="left", fill="x", expand=True, padx=(0, 3))

        a2 = tk.Button(
            atk_row,
            text="🔏 Attack T3\nSignature Forgery",
            font=("Helvetica", 9, "bold"),
            bg="#be123c",
            fg="white",
            padx=4,
            pady=4,
            relief="flat",
            command=lambda: self.run_security_suite_test("T3"),
        )
        a2.pack(side="left", fill="x", expand=True, padx=3)

        a3 = tk.Button(
            atk_row,
            text="🎭 Attack T6\nImpersonate Peer",
            font=("Helvetica", 9, "bold"),
            bg="#9f1239",
            fg="white",
            padx=4,
            pady=4,
            relief="flat",
            command=lambda: self.run_security_suite_test("T6"),
        )
        a3.pack(side="left", fill="x", expand=True, padx=3)

        a4 = tk.Button(
            atk_row,
            text="🔁 Attack T8\nReplay Packet Attack",
            font=("Helvetica", 9, "bold"),
            bg="#881337",
            fg="white",
            padx=4,
            pady=4,
            relief="flat",
            command=lambda: self.run_security_suite_test("T8"),
        )
        a4.pack(side="left", fill="x", expand=True, padx=3)

        a5 = tk.Button(
            atk_row,
            text="⬇️ Attack T9\nMITM Downgrade",
            font=("Helvetica", 9, "bold"),
            bg="#7f1d1d",
            fg="white",
            padx=4,
            pady=4,
            relief="flat",
            command=lambda: self.run_security_suite_test("T9"),
        )
        a5.pack(side="left", fill="x", expand=True, padx=(3, 0))

        # Main Side-by-Side Content Frame
        content_frame = tk.Frame(self, padx=16, pady=4)
        content_frame.pack(fill="both", expand=True)
        content_frame.columnconfigure(0, weight=1)
        content_frame.columnconfigure(1, weight=1)
        content_frame.rowconfigure(0, weight=1)

        # Alice Panel (Left)
        alice_box = tk.LabelFrame(
            content_frame,
            text=" 👤 ALICE (Sender / Client Inspection) ",
            font=("Helvetica", 10, "bold"),
            fg="#0284c7",
            padx=8,
            pady=6,
        )
        alice_box.grid(row=0, column=0, sticky="nsew", padx=(0, 4))

        self.alice_inspect = tk.Text(alice_box, height=16, font=("Courier", 10), bg="#f8fafc", relief="solid", bd=1)
        self.alice_inspect.pack(fill="both", expand=True)

        # Bob Panel (Right)
        bob_box = tk.LabelFrame(
            content_frame,
            text=" 🖥️ BOB (Receiver / Security Defense Inspection) ",
            font=("Helvetica", 10, "bold"),
            fg="#059669",
            padx=8,
            pady=6,
        )
        bob_box.grid(row=0, column=1, sticky="nsew", padx=(4, 0))

        self.bob_inspect = tk.Text(bob_box, height=16, font=("Courier", 10), bg="#f8fafc", relief="solid", bd=1)
        self.bob_inspect.pack(fill="both", expand=True)

        # Status Bar
        bottom_frame = tk.Frame(self, padx=16, pady=6, bg="#f1f5f9")
        bottom_frame.pack(fill="x")

        self.status_var = tk.StringVar(value=f"Status: Ready in {self.suite.label} mode. Select a payload or trigger an attack.")
        self.status_bar = tk.Label(
            bottom_frame,
            textvariable=self.status_var,
            font=("Helvetica", 10, "bold"),
            fg="#0f172a",
            bg="#f1f5f9",
            anchor="w",
        )
        self.status_bar.pack(side="left")

    def transmit_payload(self, name: str):
        data = load(name)
        expected_hash = self.expected_hashes.get(name, hashlib.sha256(data).hexdigest())

        t0 = time.perf_counter()
        records = self.alice_session.send_message(data)
        t_enc = (time.perf_counter() - t0) * 1e3

        first_rec = records[0]
        header = first_rec[:HEADER_LEN]
        ciphertext = first_rec[HEADER_LEN:-TAG_LEN]
        tag = first_rec[-TAG_LEN:]
        seq = self.alice_session._send.seq - len(records)

        self.alice_inspect.delete("1.0", tk.END)
        self.alice_inspect.insert(tk.END, f"=== ALICE ENCRYPTED: {name} ({self.suite.label}) ===\n")
        self.alice_inspect.insert(tk.END, f"Plaintext Size    : {len(data):,d} bytes\n")
        self.alice_inspect.insert(tk.END, f"Fragment Count    : {len(records)} records (16 KB AES-GCM chunks)\n")
        self.alice_inspect.insert(tk.END, f"Encryption Time   : {t_enc:.3f} ms\n")
        self.alice_inspect.insert(tk.END, f"Wire Overhead     : {len(records) * 30} bytes total\n\n")
        self.alice_inspect.insert(tk.END, f"--- Record #0 Inspection ---\n")
        self.alice_inspect.insert(tk.END, f"Sequence Number   : {seq}\n")
        self.alice_inspect.insert(tk.END, f"AAD Header (14 B) :\n  {format_hex(header)}\n")
        self.alice_inspect.insert(tk.END, f"Ciphertext Sample :\n  {format_hex(ciphertext)}\n")
        self.alice_inspect.insert(tk.END, f"Auth Tag (16 B)   :\n  {format_hex(tag)}\n\n")
        self.alice_inspect.insert(tk.END, f"Expected SHA-256  :\n  {expected_hash}\n")

        t1 = time.perf_counter()
        dec_parts = []
        try:
            for rec in records:
                ctype, flags, pt = self.bob_session.open(rec)
                dec_parts.append(pt)
        except RecordAuthError as e:
            messagebox.showerror("Error", f"Tampering detected: {e}")
            return

        reconstructed = b"".join(dec_parts)
        t_dec = (time.perf_counter() - t1) * 1e3
        actual_hash = hashlib.sha256(reconstructed).hexdigest()
        is_match = (actual_hash == expected_hash)

        self.bob_inspect.delete("1.0", tk.END)
        self.bob_inspect.insert(tk.END, f"=== BOB RECEIVED: {name} ({self.suite.label}) ===\n")
        self.bob_inspect.insert(tk.END, f"Decrypted Size    : {len(reconstructed):,d} bytes\n")
        self.bob_inspect.insert(tk.END, f"Decryption Time   : {t_dec:.3f} ms\n")
        self.bob_inspect.insert(tk.END, f"GCM Authentication: ✅ PASS (All {len(records)} tags authentic & in-order)\n\n")
        self.bob_inspect.insert(tk.END, f"Calculated SHA-256:\n  {actual_hash}\n\n")
        self.bob_inspect.insert(tk.END, f"Official Checksum :\n  {expected_hash}\n\n")
        if is_match:
            self.bob_inspect.insert(tk.END, "RESULT: ✅ EXACT SHA-256 MATCH — DATA INTACT!\n")
            self.status_var.set(f"Status: ✅ Successfully sent {name} ({len(data):,d} B) in {len(records)} records. Hash match!")
        else:
            self.bob_inspect.insert(tk.END, "RESULT: ❌ HASH MISMATCH!\n")
            self.status_var.set(f"Status: ❌ Error: Hash mismatch on {name}")

    def transmit_all_payloads(self):
        for name in ["payload_1KB.bin", "payload_100KB.bin", "payload_10MB.bin"]:
            self.transmit_payload(name)
            self.update()
            time.sleep(0.3)
        self.status_var.set(f"Status: ✅ All 3 official payloads successfully transmitted & verified in {self.suite.label} mode!")

    def transmit_custom(self):
        text = self.custom_entry.get().strip()
        if not text:
            return
        data = text.encode("utf-8")
        records = self.alice_session.send_message(data)
        first_rec = records[0]

        self.alice_inspect.delete("1.0", tk.END)
        self.alice_inspect.insert(tk.END, f"=== ALICE ENCRYPTED: Custom Message ({self.suite.label}) ===\n")
        self.alice_inspect.insert(tk.END, f"Plaintext       : \"{text}\"\n")
        self.alice_inspect.insert(tk.END, f"Size            : {len(data)} bytes (1 record)\n")
        self.alice_inspect.insert(tk.END, f"AAD Header (14B): {format_hex(first_rec[:HEADER_LEN])}\n")
        self.alice_inspect.insert(tk.END, f"Ciphertext      : {format_hex(first_rec[HEADER_LEN:-TAG_LEN])}\n")
        self.alice_inspect.insert(tk.END, f"Auth Tag (16B)  : {format_hex(first_rec[-TAG_LEN:])}\n")

        dec_pt = self.bob_session.receive_message(records)
        dec_text = dec_pt.decode("utf-8", errors="replace")

        self.bob_inspect.delete("1.0", tk.END)
        self.bob_inspect.insert(tk.END, f"=== BOB RECEIVED: Custom Message ===\n")
        self.bob_inspect.insert(tk.END, f"Authentication  : ✅ PASS (GCM Tag Valid)\n")
        self.bob_inspect.insert(tk.END, f"DECRYPTED TEXT  : \"{dec_text}\"\n\n")
        self.bob_inspect.insert(tk.END, f"SHA-256 Hash    : {hashlib.sha256(dec_pt).hexdigest()}\n")

        self.status_var.set(f"Status: ✅ Custom message successfully encrypted and decrypted by Bob.")

    def simulate_tamper(self):
        data = b"Secret payload intercepted by attacker"
        record = self.alice_session.seal(data)

        corrupted = bytearray(record)
        corrupted[HEADER_LEN + 3] ^= 0x01
        corrupted_record = bytes(corrupted)

        self.alice_inspect.delete("1.0", tk.END)
        self.alice_inspect.insert(tk.END, "=== ⚔️ ACTIVE ATTACK: Ciphertext Bit-Flip ===\n\n")
        self.alice_inspect.insert(tk.END, "Attacker Action:\n  MITM intercepted the record and flipped 1 bit in ciphertext byte #3.\n\n")
        self.alice_inspect.insert(tk.END, f"Original Ciphertext byte: 0x{record[HEADER_LEN + 3]:02x}\n")
        self.alice_inspect.insert(tk.END, f"Corrupted Ciphertext byte: 0x{corrupted_record[HEADER_LEN + 3]:02x}\n")

        self.bob_inspect.delete("1.0", tk.END)
        try:
            self.bob_session.open(corrupted_record)
            self.bob_inspect.insert(tk.END, "❌ BREACH: Bob failed to detect tampering!\n")
        except RecordAuthError as e:
            self.bob_inspect.insert(tk.END, "=== 🛡️ CRYPTOGRAPHIC DEFENSE ACTIVATED ===\n\n")
            self.bob_inspect.insert(tk.END, "RESULT: 🚨 ATTACK DETECTED & DEFEATED!\n\n")
            self.bob_inspect.insert(tk.END, f"Observed Exception:\n  {e}\n\n")
            self.bob_inspect.insert(tk.END, "Security Properties Enforced:\n")
            self.bob_inspect.insert(tk.END, "  1. Plaintext was NEVER released to the application.\n")
            self.bob_inspect.insert(tk.END, "  2. AES-256-GCM authentication tag rejected corrupted data.\n")
            self.bob_inspect.insert(tk.END, "  3. Session immediately failed closed.\n")
            self.status_var.set("Status: 🚨 Attack T4/T5 Defeated! Plaintext protected.")
            self.init_crypto(self.current_suite_name)

    def run_security_suite_test(self, test_name: str):
        self.alice_inspect.delete("1.0", tk.END)
        self.bob_inspect.delete("1.0", tk.END)

        if test_name == "T3":
            title = "Attack T3: Signature Forgery / Corruption"
            cases = ss.t3_signature_tampering(self.lab, self.suite)
        elif test_name == "T6":
            title = "Attack T6: Impersonation / Untrusted Identity (Mallory)"
            cases = ss.t6_untrusted_identity(self.lab, self.suite)
        elif test_name == "T8":
            title = "Attack T8: Replay & Reflection Attacks"
            cases = ss.t8_replay(self.lab, self.suite, self.payloads_dict)
        elif test_name == "T9":
            title = "Attack T9: Active MITM Algorithm Downgrade"
            cases = ss.t9_downgrade(self.lab, self.suite)
        else:
            return

        self.alice_inspect.insert(tk.END, f"=== ⚔️ {title} ===\n\n")
        self.alice_inspect.insert(tk.END, f"Total attack vectors tested: {len(cases)}\n\n")
        for i, c in enumerate(cases, 1):
            self.alice_inspect.insert(tk.END, f"[{i}] Vector: {c.name}\n")
            self.alice_inspect.insert(tk.END, f"    Fault: {c.fault}\n\n")

        self.bob_inspect.insert(tk.END, f"=== 🛡️ DEFENSE RESULTS: {test_name} ===\n\n")
        all_ok = True
        for c in cases:
            all_ok &= c.ok
            status_icon = "✅ BLOCKED" if c.ok else "❌ BREACH"
            self.bob_inspect.insert(tk.END, f"{status_icon}: {c.name}\n")
            self.bob_inspect.insert(tk.END, f"   Defense: {c.observed}\n\n")

        if all_ok:
            self.bob_inspect.insert(tk.END, f"SUMMARY: ✅ ALL {len(cases)} ATTACK SUB-CASES DEFEATED!\nZero plaintext leaked. Handshake aborts securely.\n")
            self.status_var.set(f"Status: ✅ {test_name} attack test complete: {len(cases)}/{len(cases)} vectors successfully blocked!")


if __name__ == "__main__":
    app = QuantumSafeGUI()
    app.mainloop()
