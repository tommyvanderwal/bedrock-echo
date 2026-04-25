"""Bedrock Echo node-side client (v1).

Stateful enough to track timestamps and auto-bootstrap on UNKNOWN_SOURCE.
The flow is HEARTBEAT-first: we try heartbeat, and only fall back to
BOOTSTRAP if the witness replies UNKNOWN_SOURCE (per PROTOCOL.md §13).
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
        """Send a BOOTSTRAP, wait for ACK. Caller-friendly fallback used
        only when HEARTBEAT-first hits UNKNOWN_SOURCE."""
        eph_priv, _ = crypto.x25519_generate()
        bs = proto.Bootstrap(
            sender_id=self.sender_id,
            timestamp_ms=self._next_ts(),
            cluster_key=self.cluster_key,
        )
        wire = bs.encode(self.witness_pubkey, eph_priv)
        reply = self._sendrecv(wire)
        ack = proto.decode_bootstrap_ack(reply, self.cluster_key)
        log.info("bootstrap OK: status=%d witness_uptime=%ds",
                 ack.status, ack.witness_uptime_seconds)
        return ack

    # ── DISCOVER ──

    def discover(self) -> proto.UnknownSource:
        """Send a DISCOVER probe. Returns the witness's UNKNOWN_SOURCE reply
        (which carries the witness's pubkey for verification)."""
        d = proto.Discover(sender_id=self.sender_id, timestamp_ms=self._next_ts())
        reply = self._sendrecv(d.encode())
        return proto.decode_unknown_source(reply)

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

    # ── core heartbeat with auto-bootstrap on UNKNOWN_SOURCE ──

    def _heartbeat_core(self, target: int, own_payload: bytes) -> bytes:
        hb = proto.Heartbeat(
            sender_id=self.sender_id,
            timestamp_ms=self._next_ts(),
            query_target_id=target,
            own_payload=own_payload,
        )
        reply = self._sendrecv(hb.encode(self.cluster_key))
        # If it's UNKNOWN_SOURCE, bootstrap once then retry.
        if len(reply) == proto.UNKNOWN_SOURCE_LEN and reply[4] == proto.MSG_UNKNOWN_SOURCE:
            us = proto.decode_unknown_source(reply)
            if us.witness_pubkey != self.witness_pubkey:
                raise proto.AuthError(
                    "witness returned UNKNOWN_SOURCE but pubkey mismatch — "
                    "possible MITM, refusing to BOOTSTRAP"
                )
            log.info("witness returned UNKNOWN_SOURCE, bootstrapping")
            self.bootstrap()
            hb = proto.Heartbeat(
                sender_id=self.sender_id,
                timestamp_ms=self._next_ts(),
                query_target_id=target,
                own_payload=own_payload,
            )
            reply = self._sendrecv(hb.encode(self.cluster_key))
        return reply
