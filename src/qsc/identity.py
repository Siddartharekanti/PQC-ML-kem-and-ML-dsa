"""Long-term identities and the pinned trust store (trust anchor).

Trust model: every endpoint is provisioned out of band with the *public* identity keys of
the peers it may talk to (a pin per (identity name, signature algorithm)). Keys or
fingerprints received over the network are never trusted by themselves: the wire only
carries a 32-byte key id (SHA-256 of the public key) so the receiver can fail fast with a
clear error; the signature is always verified with the locally pinned key.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field

from .errors import UntrustedIdentity
from .suites import SIG_ALGS


def key_id(pk_bytes: bytes) -> bytes:
    return hashlib.sha256(pk_bytes).digest()


@dataclass
class Identity:
    name: str
    sig_alg: str
    sk: object = field(repr=False)
    pk: bytes = field(repr=False)

    @property
    def key_id(self) -> bytes:
        return key_id(self.pk)

    @classmethod
    def generate(cls, name: str, sig_alg: str) -> "Identity":
        sk, pk = SIG_ALGS[sig_alg].keygen()
        return cls(name, sig_alg, sk, pk)

    def sign(self, msg: bytes, ctx: bytes) -> bytes:
        return SIG_ALGS[self.sig_alg].sign(self.sk, msg, ctx)

    # --- persistence (used only by the TCP demo / provisioning script) ------------
    def save(self, directory: str) -> str:
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, f"{self.name}.{self.sig_alg}.key.json")
        raw = SIG_ALGS[self.sig_alg].dump_private(self.sk)
        with open(path, "w") as f:
            json.dump({"name": self.name, "sig_alg": self.sig_alg, "private_raw_hex": raw.hex(),
                       "public_hex": self.pk.hex()}, f, indent=2)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return path

    @classmethod
    def load(cls, path: str) -> "Identity":
        d = json.load(open(path))
        alg = SIG_ALGS[d["sig_alg"]]
        sk = alg.load_private(bytes.fromhex(d["private_raw_hex"]))
        pk = sk.public_key().public_bytes_raw()
        if pk.hex() != d["public_hex"]:
            raise ValueError(f"{path}: public key does not match private key")
        return cls(d["name"], d["sig_alg"], sk, pk)


class TrustStore:
    """Pinned public verification keys: (identity name, signature algorithm) -> public key."""

    def __init__(self):
        self._pins: dict = {}

    def pin(self, name: str, sig_alg: str, pk: bytes) -> None:
        self._pins[(name, sig_alg)] = bytes(pk)

    def pin_identity(self, ident: Identity) -> None:
        self.pin(ident.name, ident.sig_alg, ident.pk)

    def lookup(self, name: str, sig_alg: str, claimed_key_id: bytes) -> bytes:
        """Return the pinned key for `name`, after checking the claimed key id matches it."""
        pk = self._pins.get((name, sig_alg))
        if pk is None:
            raise UntrustedIdentity(f"identity '{name}' ({sig_alg}) is not in the trust store")
        if key_id(pk) != claimed_key_id:
            raise UntrustedIdentity(
                f"key presented for '{name}' (key id {claimed_key_id.hex()[:16]}...) does not match "
                f"the pinned trust anchor (key id {key_id(pk).hex()[:16]}...)")
        return pk

    def __contains__(self, item) -> bool:
        return item in self._pins

    # --- persistence ---------------------------------------------------------------
    def save(self, path: str) -> None:
        with open(path, "w") as f:
            json.dump([{"name": n, "sig_alg": a, "public_hex": pk.hex(), "key_id": key_id(pk).hex()}
                       for (n, a), pk in sorted(self._pins.items())], f, indent=2)

    @classmethod
    def load(cls, path: str) -> "TrustStore":
        ts = cls()
        for e in json.load(open(path)):
            pk = bytes.fromhex(e["public_hex"])
            if key_id(pk).hex() != e["key_id"]:
                raise ValueError(f"{path}: corrupted pin for {e['name']}")
            ts.pin(e["name"], e["sig_alg"], pk)
        return ts
