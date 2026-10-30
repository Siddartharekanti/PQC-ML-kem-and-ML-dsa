"""Provisioning helper used by tests and benchmarks: builds a small PKI-less deployment.

    alice   - client, trusted by bob and charlie
    carol   - second client, trusted by bob          (used for identity-swap tests)
    bob     - server, pinned by alice and carol
    charlie - second server, pinned by alice         (a *trusted* but *different* peer)
    mallory - attacker; holds valid keys of every algorithm but is pinned by nobody

Long-term identity keys are generated once per Lab (provisioning time) and are never part
of the measured handshake latency.
"""
from __future__ import annotations

from .handshake import ClientHandshake, ReplayCache, ServerConfig, ServerHandshake, run_handshake
from .identity import Identity, TrustStore
from .suites import CLASSICAL, HYBRID, PQC, SIG_ALGS

NAMES = ("alice", "carol", "bob", "charlie", "mallory")


class Lab:
    def __init__(self, server_suites=(PQC,), sig_algs=None):
        algs = sig_algs or tuple(SIG_ALGS)
        self.ids = {n: {a: Identity.generate(n, a) for a in algs} for n in NAMES}
        self.trust = {n: TrustStore() for n in NAMES}
        for a in algs:
            for client in ("alice", "carol"):
                self.trust["bob"].pin_identity(self.ids[client][a])
            self.trust["charlie"].pin_identity(self.ids["alice"][a])
            for server in ("bob", "charlie"):
                self.trust["alice"].pin_identity(self.ids[server][a])
            self.trust["carol"].pin_identity(self.ids["bob"][a])
        self.server_suites = tuple(server_suites)
        self.server_cfg = {s: ServerConfig(s, self.ids[s].values(), self.trust[s], self.server_suites,
                                           ReplayCache()) for s in ("bob", "charlie")}

    def client(self, suite=PQC, name="alice", server="bob", identity_of=None) -> ClientHandshake:
        ident = self.ids[identity_of or name][suite.sig_name]
        if identity_of:  # attacker reusing someone else's *name* but its own key
            ident = Identity(name, ident.sig_alg, ident.sk, ident.pk)
        trust = self.trust[name] if name in ("alice", "carol") else self.trust["alice"]  # pins are public
        return ClientHandshake(ident, trust, server, suite)

    def server(self, name="bob", allowed=None, replay_cache=None) -> ServerHandshake:
        base = self.server_cfg[name]
        if allowed is None and replay_cache is None:
            return ServerHandshake(base)
        cfg = ServerConfig(name, base.identities.values(), base.trust,
                           allowed or self.server_suites, replay_cache or base.replay_cache)
        return ServerHandshake(cfg)

    def handshake(self, suite=PQC, tamper=None, client=None, server=None):
        return run_handshake(client or self.client(suite), server or self.server(), tamper)


__all__ = ["Lab", "PQC", "CLASSICAL", "HYBRID"]
