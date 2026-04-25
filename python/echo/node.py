"""Bedrock Echo node-side client (v1).

Stateful enough to track timestamps, cache the witness's anti-spoof
cookie, and auto-bootstrap on INIT or on heartbeat timeout (which can
mean a rate-limited INIT that got silently dropped).

The flow is HEARTBEAT-first: we try heartbeat, and only fall back to
BOOTSTRAP if the witness replies INIT (per PROTOCOL.md §13) or doesn't
reply at all (likely rate-limited). The cached cookie is what makes
the BOOTSTRAP valid; if we don't have one yet, we DISCOVER first.
"""
from __future__ import annotations

import logging
import socket
import time
from dataclasses import dataclass

from . import proto, crypto

log = logging.getLogger("echo.node")


@dataclass
class NodeClient:
    sender_id: int                           # 0x00..0xFE
    cluster_key: bytes                       # 32 bytes
    witness_addr: tuple[str, int]            # (host, port)
    witness_pubkey: bytes                    # X25519 public, 32 bytes
    recv_timeout_s: float = 2.0
    _last_sent_ts: int = 0
    _cached_cookie: bytes | None = None      # last cookie seen in INIT

    def __post_init__(self):
        if not (0 <= self.sender_id <= proto.NODE_SENDER_ID_MAX):
            raise ValueError("sender_id must be 0..0xFE")
        if len(self.cluster_key) != proto.CLUSTER_KEY_LEN:
            raise ValueError("cluster_key must be 32 bytes")
        if len(self.witness_pubkey) != proto.WITNESS_PUBKEY_LEN:
            raise ValueError("witness_pubkey must be 32 bytes")

    def _next_ts(self) -> int:
        """Strict-monotonic-per-sender timestamp_ms (PROTOCOL.md §6.1)."""
        now = time.time_ns() // 1_000_000
        ts = max(now, self._last_sent_ts + 1)
        self._last_sent_ts = ts
        return ts

    def _sendrecv(self, wire: bytes, sock: socket.socket | None = None) -> bytes:
        """Send one packet, wait for one reply, return reply bytes."""
        owned = sock is None
        if owned:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.recv_timeout_s)
        try:
            sock.sendto(wire, self.witness_addr)
            data, _ = sock.recvfrom(proto.MTU_CAP + 64)
            return data
        finally:
            if owned:
                sock.close()

    # ── BOOTSTRAP ──

    def bootstrap(self) -> proto.BootstrapAck:
        """Send a BOOTSTRAP carrying the cached cookie, wait for ACK.

        Caller is responsible for ensuring `self._cached_cookie` is set
        before calling — typically by either receiving an INIT reply
        (auto-cached on `_handle_init_reply`) or by calling `discover()`
        explicitly. If no cookie is cached, we transparently call
        `discover()` here to fetch one.
        """
        if self._cached_cookie is None:
            self.discover()  # populates self._cached_cookie
        eph_priv, _ = crypto.x25519_generate()
        bs = proto.Bootstrap(
            sender_id=self.sender_id,
            timestamp_ms=self._next_ts(),
            cluster_key=self.cluster_key,
            cookie=self._cached_cookie,
        )
        wire = bs.encode(self.witness_pubkey, eph_priv)
        reply = self._sendrecv(wire)
        ack = proto.decode_bootstrap_ack(reply, self.cluster_key)
        log.info("bootstrap OK: status=%d witness_uptime=%ds",
                 ack.status, ack.witness_uptime_seconds)
        return ack

    # ── DISCOVER ──

    def discover(self) -> proto.Init:
        """Send a DISCOVER probe. Returns the witness's INIT reply
        (carrying witness_pubkey + a fresh cookie for our src_ip).
        Caches the cookie for use by subsequent BOOTSTRAPs."""
        d = proto.Discover(sender_id=self.sender_id, timestamp_ms=self._next_ts())
        reply = self._sendrecv(d.encode())
        init = proto.decode_init(reply)
        self._cached_cookie = init.cookie
        return init

    # ── HEARTBEAT — list query (peers + self) ──

    def heartbeat_list(self, own_payload: bytes = b"") -> proto.StatusList:
        reply = self._heartbeat_core(proto.QUERY_LIST_SENTINEL, own_payload)
        return proto.decode_status_list(reply, self.cluster_key)

    # ── HEARTBEAT — detail query (one peer, may be self) ──

    def heartbeat_detail(self, peer_sender_id: int,
                         own_payload: bytes = b"") -> proto.StatusDetail:
        if not (0 <= peer_sender_id <= proto.NODE_SENDER_ID_MAX):
            raise ValueError("peer_sender_id must be 0..0xFE")
        reply = self._heartbeat_core(peer_sender_id, own_payload)
        return proto.decode_status_detail(reply, self.cluster_key)

    # ── core heartbeat with auto-bootstrap on INIT ──

    def _heartbeat_core(self, target: int, own_payload: bytes) -> bytes:
        hb = proto.Heartbeat(
            sender_id=self.sender_id,
            timestamp_ms=self._next_ts(),
            query_target_id=target,
            own_payload=own_payload,
        )
        try:
            reply = self._sendrecv(hb.encode(self.cluster_key))
        except (TimeoutError, socket.timeout):
            # Witness might be rate-limiting INIT (1/s/IP). With cookies
            # gating BOOTSTRAP, we need a fresh cookie before bootstrap —
            # so DISCOVER first, which populates self._cached_cookie, then
            # BOOTSTRAP, then retry the heartbeat. DISCOVER is authenticated
            # at the application layer by checking witness_pubkey, and the
            # subsequent BOOTSTRAP is X25519-ECDH-bound to witness_pubkey,
            # so a rogue witness on the path can't trick us.
            log.info("heartbeat timed out (likely rate-limited INIT); "
                     "discovering + bootstrapping")
            init = self.discover()
            if init.witness_pubkey != self.witness_pubkey:
                raise proto.AuthError(
                    "discover returned pubkey mismatch — possible MITM, "
                    "refusing to BOOTSTRAP"
                )
            self.bootstrap()
            hb = proto.Heartbeat(
                sender_id=self.sender_id,
                timestamp_ms=self._next_ts(),
                query_target_id=target,
                own_payload=own_payload,
            )
            return self._sendrecv(hb.encode(self.cluster_key))

        # If it's INIT, cache the cookie, bootstrap once, then retry.
        if len(reply) == proto.INIT_LEN and reply[4] == proto.MSG_INIT:
            init = proto.decode_init(reply)
            if init.witness_pubkey != self.witness_pubkey:
                raise proto.AuthError(
                    "witness returned INIT but pubkey mismatch — "
                    "possible MITM, refusing to BOOTSTRAP"
                )
            self._cached_cookie = init.cookie
            log.info("witness returned INIT, bootstrapping with fresh cookie")
            self.bootstrap()
            hb = proto.Heartbeat(
                sender_id=self.sender_id,
                timestamp_ms=self._next_ts(),
                query_target_id=target,
                own_payload=own_payload,
            )
            reply = self._sendrecv(hb.encode(self.cluster_key))
        return reply
