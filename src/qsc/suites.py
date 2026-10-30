"""Cipher suites: thin wrappers around the vetted `cryptography` library.

No primitive is implemented here. Each suite only maps the same protocol operations
(ephemeral KEM, identity signature) onto library calls, so the PQC suite and the
classical baseline run *exactly the same* handshake code.

  Suite 0x0101  PQC        ML-KEM-768 (FIPS 203) + ML-DSA-65 (FIPS 204) + HKDF-SHA256 + AES-256-GCM
  Suite 0x0201  CLASSICAL  X25519 (RFC 7748)     + Ed25519 (RFC 8032)    + HKDF-SHA256 + AES-256-GCM
  Suite 0x0301  HYBRID     X25519+ML-KEM-768      + ML-DSA-65             + HKDF-SHA256 + AES-256-GCM
                (extension, used only for the deployment recommendation; not the baseline)

X25519 is used as a KEM in the usual way: the "public key" is the initiator's ephemeral
X25519 key, the "ciphertext" is the responder's ephemeral X25519 key, and the shared
secret is the X25519 output.
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa, mlkem, x25519

from .errors import KEMError, SignatureError

KDF_NAME = "HKDF-SHA256"
AEAD_NAME = "AES-256-GCM"


# ----------------------------------------------------------------------------- KEMs
class _MLKEM768:
    name = "ML-KEM-768"
    pk_len, ct_len, ss_len = 1184, 1088, 32

    @staticmethod
    def keygen():
        sk = mlkem.MLKEM768PrivateKey.generate()
        return sk, sk.public_key().public_bytes_raw()

    @staticmethod
    def encap(pk_bytes: bytes):
        try:
            ss, ct = mlkem.MLKEM768PublicKey.from_public_bytes(pk_bytes).encapsulate()
        except ValueError as e:  # FIPS 203 encapsulation-key check failed
            raise KEMError(f"ML-KEM-768 public key rejected: {e}") from e
        return ss, ct

    @staticmethod
    def decap(sk, ct: bytes) -> bytes:
        try:
            return sk.decapsulate(ct)  # implicit rejection: wrong ct -> pseudo-random secret
        except ValueError as e:
            raise KEMError(f"ML-KEM-768 ciphertext rejected: {e}") from e


class _X25519:
    name = "X25519"
    pk_len, ct_len, ss_len = 32, 32, 32

    @staticmethod
    def keygen():
        sk = x25519.X25519PrivateKey.generate()
        return sk, sk.public_key().public_bytes_raw()

    @staticmethod
    def encap(pk_bytes: bytes):
        try:
            eph = x25519.X25519PrivateKey.generate()
            ss = eph.exchange(x25519.X25519PublicKey.from_public_bytes(pk_bytes))
        except ValueError as e:  # e.g. low-order point -> all-zero output
            raise KEMError(f"X25519 public key rejected: {e}") from e
        return ss, eph.public_key().public_bytes_raw()

    @staticmethod
    def decap(sk, ct: bytes) -> bytes:
        try:
            return sk.exchange(x25519.X25519PublicKey.from_public_bytes(ct))
        except ValueError as e:
            raise KEMError(f"X25519 peer key rejected: {e}") from e


class _HybridX25519MLKEM768:
    """Concatenation combiner as in the IETF X25519MLKEM768 TLS group: ss = ss_mlkem || ss_x25519."""

    name = "X25519+ML-KEM-768"
    pk_len, ct_len, ss_len = 32 + 1184, 32 + 1088, 64

    @staticmethod
    def keygen():
        xs, xp = _X25519.keygen()
        ms, mp = _MLKEM768.keygen()
        return (xs, ms), xp + mp

    @staticmethod
    def encap(pk_bytes: bytes):
        x_ss, x_ct = _X25519.encap(pk_bytes[:32])
        m_ss, m_ct = _MLKEM768.encap(pk_bytes[32:])
        return m_ss + x_ss, x_ct + m_ct

    @staticmethod
    def decap(sk, ct: bytes) -> bytes:
        xs, ms = sk
        return _MLKEM768.decap(ms, ct[32:]) + _X25519.decap(xs, ct[:32])


# ----------------------------------------------------------------------------- signatures
class _MLDSA65:
    name = "ML-DSA-65"
    pk_len, sig_len = 1952, 3309

    @staticmethod
    def keygen():
        sk = mldsa.MLDSA65PrivateKey.generate()
        return sk, sk.public_key().public_bytes_raw()

    @staticmethod
    def sign(sk, msg: bytes, ctx: bytes) -> bytes:
        return sk.sign(msg, ctx)  # FIPS 204 context string = domain separation

    @staticmethod
    def verify(pk_bytes: bytes, sig: bytes, msg: bytes, ctx: bytes) -> None:
        try:
            mldsa.MLDSA65PublicKey.from_public_bytes(pk_bytes).verify(sig, msg, ctx)
        except InvalidSignature as e:
            raise SignatureError("ML-DSA-65 signature verification failed (InvalidSignature)") from e

    @staticmethod
    def load_private(raw: bytes):
        return mldsa.MLDSA65PrivateKey.from_seed_bytes(raw)

    @staticmethod
    def dump_private(sk) -> bytes:
        return sk.private_bytes_raw()  # 32-byte FIPS 204 seed


class _Ed25519:
    name = "Ed25519"
    pk_len, sig_len = 32, 64

    @staticmethod
    def _frame(msg: bytes, ctx: bytes) -> bytes:
        # Ed25519 (pure) has no context input; prepend a length-prefixed context instead.
        return len(ctx).to_bytes(1, "big") + ctx + msg

    @staticmethod
    def keygen():
        sk = ed25519.Ed25519PrivateKey.generate()
        return sk, sk.public_key().public_bytes_raw()

    @classmethod
    def sign(cls, sk, msg: bytes, ctx: bytes) -> bytes:
        return sk.sign(cls._frame(msg, ctx))

    @classmethod
    def verify(cls, pk_bytes: bytes, sig: bytes, msg: bytes, ctx: bytes) -> None:
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(pk_bytes).verify(sig, cls._frame(msg, ctx))
        except InvalidSignature as e:
            raise SignatureError("Ed25519 signature verification failed (InvalidSignature)") from e

    @staticmethod
    def load_private(raw: bytes):
        return ed25519.Ed25519PrivateKey.from_private_bytes(raw)

    @staticmethod
    def dump_private(sk) -> bytes:
        return sk.private_bytes_raw()


# ----------------------------------------------------------------------------- suites
@dataclass(frozen=True)
class Suite:
    suite_id: int
    label: str
    kem: type
    sig: type
    is_baseline: bool = False

    @property
    def alg_string(self) -> str:
        """Exact algorithm identifiers carried (and signed) in ClientHello / ServerHello."""
        return f"{self.kem.name},{self.sig.name},{KDF_NAME},{AEAD_NAME}"

    @property
    def sig_name(self) -> str:
        return self.sig.name

    def __str__(self) -> str:
        return f"{self.label} (0x{self.suite_id:04x}: {self.alg_string})"


PQC = Suite(0x0101, "PQC", _MLKEM768, _MLDSA65)
CLASSICAL = Suite(0x0201, "CLASSICAL", _X25519, _Ed25519, is_baseline=True)
HYBRID = Suite(0x0301, "HYBRID", _HybridX25519MLKEM768, _MLDSA65)

SUITES = {s.suite_id: s for s in (PQC, CLASSICAL, HYBRID)}
BY_LABEL = {s.label.lower(): s for s in SUITES.values()}
SIG_ALGS = {_MLDSA65.name: _MLDSA65, _Ed25519.name: _Ed25519}


def get_suite(name_or_id) -> Suite:
    if isinstance(name_or_id, Suite):
        return name_or_id
    if isinstance(name_or_id, int):
        return SUITES[name_or_id]
    return BY_LABEL[str(name_or_id).lower()]
