"""Bedrock Echo node-side client.

Intended for use by the Python node daemon (successor to bedrock-failover.py).
Stateful enough to track sequence numbers and auto-bootstrap on UNKNOWN_SOURCE.
"""
from __future__ import annotations

import logging
import socket
import time
from dataclasses import dataclass, field
from typing import Optional

from . import proto, crypto
from .proto import (
    Heartbeat, StatusList, StatusDetail, UnknownSource,
    Bootstrap, BootstrapAck, Header,
    ProtocolError, AuthError,
    MSG_STATUS_LIST, MSG_STATUS_DETAIL, MSG_UNKNOWN_SOURCE, MSG_BOOTSTRAP_ACK,
    HEADER_LEN, HMAC_LEN, MTU_CAP,
)

log = logging.getLogger("echo.node")


@dataclass
class NodeClient:
    sender_id: bytes                         # this node's 8-byte id
    cluster_key: bytes                       # 32 bytes
    witness_addr: tuple[str, int]            # (host, port)
    witness_x25519_pub: bytes                # 32 bytes
    recv_timeout_s: float = 2.0
    _last_sent_seq: int = 0
    _last_rx_seq: int = 0

    def __post_init__(self):
        if len(self.sender_id) != 8:
            raise ValueError("sender_id must be 8 bytes")
        if len(self.cluster_key) != 32:
            raise ValueError("cluster_key must be 32 bytes")
        if len(self.witness_x25519_pub) != 32:
            raise ValueError("witness_x25519_pub must be 32 bytes")

    def _next_seq(self) -> int:
        now = time.time_ns() // 1_000_000
        s = max(now, self._last_sent_seq + 1)
        self._last_sent_seq = s
        return s

    def _sendrecv(self, wire: bytes, sock: Optional[socket.socket] = None) -> bytes:
        """Send one packet, wait for exactly one reply. Returns the reply bytes."""
        owned = sock is None
        if owned:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.recv_timeout_s)
        try:
            sock.sendto(wire, self.witness_addr)
            data, _ = sock.recvfrom(MTU_CAP + 64)
            return data
        finally:
            if owned:
                sock.close()

    def bootstrap(self, init_payload: bytes = b"") -> BootstrapAck:
        eph_priv, _ = crypto.x25519_generate()
        bs = Bootstrap(
            sender_id=self.sender_id,
            sequence=self._next_seq(),
            timestamp_ms=time.time_ns() // 1_000_000,
            cluster_key=self.cluster_key,
            init_payload=init_payload,
        )
        wire = bs.encode(self.witness_x25519_pub, eph_priv)
        reply = self._sendrecv(wire)
        ack = proto.decode_bootstrap_ack(reply, self.cluster_key)
        log.info("bootstrap OK: status=%d witness_uptime=%dms",
                 ack.status, ack.witness_uptime_ms)
        self._last_rx_seq = ack.sequence
        return ack

    def heartbeat_list(self, own_payload: bytes = b"") -> StatusList:
        """Send a heartbeat asking for the full peer list. Auto-bootstraps
        on UNKNOWN_SOURCE."""
        reply = self._heartbeat_core(b"\x00" * 8, own_payload)
        return proto.decode_status_list(reply, self.cluster_key)

    def heartbeat_detail(self, peer_sender_id: bytes,
                         own_payload: bytes = b"") -> StatusDetail:
        """Send a heartbeat asking for the detailed state of one peer.
        Auto-bootstraps on UNKNOWN_SOURCE."""
        if len(peer_sender_id) != 8 or peer_sender_id == b"\x00" * 8:
            raise ValueError("peer_sender_id must be 8 non-zero bytes")
        reply = self._heartbeat_core(peer_sender_id, own_payload)
        return proto.decode_status_detail(reply, self.cluster_key)

    def _heartbeat_core(self, target: bytes, own_payload: bytes) -> bytes:
        hb = Heartbeat(
            sender_id=self.sender_id,
            sequence=self._next_seq(),
            timestamp_ms=time.time_ns() // 1_000_000,
            query_target_id=target,
            own_payload=own_payload,
        )
        wire = hb.encode(self.cluster_key)
        reply = self._sendrecv(wire)
        # If it's UNKNOWN_SOURCE we bootstrap then retry once.
        if len(reply) >= HEADER_LEN and reply[4] == MSG_UNKNOWN_SOURCE:
            log.info("witness returned UNKNOWN_SOURCE, re-bootstrapping")
            self.bootstrap()
            # retry the heartbeat
            hb = Heartbeat(
                sender_id=self.sender_id,
                sequence=self._next_seq(),
                timestamp_ms=time.time_ns() // 1_000_000,
                query_target_id=target,
                own_payload=own_payload,
            )
            wire = hb.encode(self.cluster_key)
            reply = self._sendrecv(wire)
        return reply
