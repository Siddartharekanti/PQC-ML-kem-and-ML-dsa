"""
QFF 2026 Phase 2 - PS-P1 primitives quick-start.

Shows the exact library calls for every primitive PS-P1 requires. It is NOT a protocol:
it has no roles, no transcript binding, no identity checks and no replay protection.
Designing and implementing those is your job.

    python P1_secure_channel/primitives_quickstart.py
"""
import os

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --- ML-KEM-768 (FIPS 203): key establishment ---------------------------------
kem_sk = mlkem.MLKEM768PrivateKey.generate()
kem_pk_bytes = kem_sk.public_key().public_bytes_raw()                  # 1184 bytes on the wire
peer_pk = mlkem.MLKEM768PublicKey.from_public_bytes(kem_pk_bytes)
shared_secret, kem_ct = peer_pk.encapsulate()                          # 32-byte secret, 1088-byte ciphertext
assert kem_sk.decapsulate(kem_ct) == shared_secret

# --- ML-DSA-65 (FIPS 204): authentication ----------------------------------------
id_sk = mldsa.MLDSA65PrivateKey.generate()
id_pk_bytes = id_sk.public_key().public_bytes_raw()                    # 1952 bytes - pin / distribute this
message = b"bytes you choose to authenticate (hint: the whole transcript)"
sig = id_sk.sign(message)                                              # 3309 bytes
mldsa.MLDSA65PublicKey.from_public_bytes(id_pk_bytes).verify(sig, message)
try:
    mldsa.MLDSA65PublicKey.from_public_bytes(id_pk_bytes).verify(sig, message + b"!")
except InvalidSignature:
    print("modified message -> InvalidSignature (expected)")

# --- HKDF-SHA256: derive traffic keys ---------------------------------------------
salt = os.urandom(32)
k_c2s = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"QFF26 c2s").derive(shared_secret)
k_s2c = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"QFF26 s2c").derive(shared_secret)

# --- AES-256-GCM: authenticated encryption ----------------------------------------
nonce = os.urandom(12)              # never reuse a nonce with the same key (a counter is a good design)
aad = b"header bytes you want authenticated but not encrypted"
ct = AESGCM(k_c2s).encrypt(nonce, b"hello Bob", aad)
assert AESGCM(k_c2s).decrypt(nonce, ct, aad) == b"hello Bob"
bad = bytearray(ct); bad[-1] ^= 1
try:
    AESGCM(k_c2s).decrypt(nonce, bytes(bad), aad)
except InvalidTag:
    print("modified ciphertext/tag -> InvalidTag (expected)")

print(f"sizes: ML-KEM pk={len(kem_pk_bytes)} ct={len(kem_ct)} | ML-DSA pk={len(id_pk_bytes)} sig={len(sig)} "
      f"| AES-GCM overhead={len(ct) - len(b'hello Bob')} B tag + 12 B nonce")

# Classical baseline equivalents (for the required baseline comparison):
#   from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
#   x25519.X25519PrivateKey.generate() ... .exchange(peer_public_key)
#   ed25519.Ed25519PrivateKey.generate() ... .sign(msg) / .public_key().verify(sig, msg)
