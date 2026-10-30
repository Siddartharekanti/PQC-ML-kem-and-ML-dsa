"""Exception hierarchy.

Every failure is fail-closed: the object that raised it (handshake state machine or
record-layer session) is moved to a terminal FAILED/CLOSED state and wipes its key
material, so no traffic key from a failed handshake can ever be used.
"""


class QSCError(Exception):
    """Base class for every protocol error."""

    code = "error"


# --------------------------------------------------------------------------- handshake
class HandshakeError(QSCError):
    """Handshake aborted. No traffic keys are released."""

    code = "handshake_abort"


class DecodeError(HandshakeError):
    """Malformed message: wrong type, length, field order, field size or trailing bytes."""

    code = "decode_error"


class ProtocolStateError(HandshakeError):
    """Message received in the wrong state (e.g. a second ClientHello, or use after failure)."""

    code = "state_error"


class DowngradeError(HandshakeError):
    """Suite / algorithm identifiers not allowed by policy or inconsistent with the offer."""

    code = "downgrade_or_unsupported"


class UntrustedIdentity(HandshakeError):
    """Peer identity unknown, or its key fingerprint does not match the pinned trust anchor."""

    code = "untrusted_identity"


class IdentityMismatch(HandshakeError):
    """Peer names a different party than the one this session is bound to (misbinding / swap)."""

    code = "identity_mismatch"


class SignatureError(HandshakeError):
    """ML-DSA / Ed25519 verification of the transcript signature failed (InvalidSignature)."""

    code = "invalid_signature"


class FinishedError(HandshakeError):
    """Finished MAC (key confirmation) did not verify."""

    code = "finished_mismatch"


class KEMError(HandshakeError):
    """KEM public key / ciphertext rejected by the library (e.g. invalid X25519 point)."""

    code = "kem_error"


class HandshakeReplayError(HandshakeError):
    """A ClientHello nonce that this server has already seen."""

    code = "handshake_replay"


# --------------------------------------------------------------------------- record layer
class RecordError(QSCError):
    """Record-layer failure; the session is closed."""

    code = "record_error"


class RecordAuthError(RecordError):
    """AES-GCM authentication failed (cryptography.exceptions.InvalidTag). No plaintext released."""

    code = "InvalidTag"


class ReplayError(RecordError):
    """Record sequence number already consumed (replay) or out of order."""

    code = "record_replay"


class SessionClosed(RecordError):
    """Session already closed because of an earlier fatal error."""

    code = "session_closed"
