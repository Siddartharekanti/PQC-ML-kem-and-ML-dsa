"""qsc - Quantum-Safe Secure Channel (QFF 2026 Phase 2, PS-P1). Research prototype, not production."""
from .handshake import ClientHandshake, ReplayCache, ServerConfig, ServerHandshake, run_handshake  # noqa: F401
from .identity import Identity, TrustStore  # noqa: F401
from .record import Session  # noqa: F401
from .suites import CLASSICAL, HYBRID, PQC, SUITES, get_suite  # noqa: F401

__version__ = "1.0.0"

__all__ = ["ClientHandshake", "ReplayCache", "ServerConfig", "ServerHandshake", "run_handshake", "Identity",
           "TrustStore", "Session", "CLASSICAL", "HYBRID", "PQC", "SUITES", "get_suite"]
