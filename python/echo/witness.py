"""Stateful Bedrock Echo witness.

RAM-only state. All dispatch / validation / silent-drop logic per PROTOCOL.md.
The UDP loop is a plain blocking socket — trivially portable and easy to unit
test (see `feed_packet` for a packet-at-a-time driver used by tests).
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import socket
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import proto, crypto
from .proto import (
    Header, Heartbeat, StatusList, StatusDetail, UnknownSource,
    Bootstrap, BootstrapAck, ListEntry,
    ProtocolError, AuthError,
    MSG_HEARTBEAT, MSG_BOOTSTRAP,
    MAGIC, HEADER_LEN, HMAC_LEN, MTU_CAP,
    CLUSTER_KEY_LEN, LIST_MAX_ENTRIES,
)

log = logging.getLogger("echo.witness")

MAX_NODES = 64
MAX_CLUSTERS = 32
MAX_TRACKED_IPS = 128

# token bucket defaults (§11)
RL_RATE_PER_SEC = 10
RL_BURST = 20
RL_UNKNOWN_PER_SEC = 1

# age-out tiers (§10), (threshold_inclusive, timeout_ms)
# Generous at normal fill — supports the recovery-after-outage pattern
# (Appendix A) across multi-day planned outages. Only kick into aggressive
# reclaim when genuinely overloaded.
AGE_OUT_TIERS = (
    (int(MAX_NODES * 0.80), 72 * 3600 * 1000),   # 0–80%: 72h
    (int(MAX_NODES * 0.90), 4 * 3600 * 1000),    # 80–90%: 4h
    (MAX_NODES, 5 * 60 * 1000),                  # >90%: 5min
)


# ── State dataclasses ──────────────────────────────────────────────────────


@dataclass
class ClusterEntry:
    cluster_slot: int
    cluster_key: bytes
    bootstrapped_ms: int
    num_nodes: int = 0


@dataclass
class NodeEntry:
    sender_id: bytes
    sender_ipv4: bytes
    cluster_slot: int
    last_rx_ms: int
    last_rx_sequence: int = 0
    last_tx_sequence: int = 0
    payload: bytes = b""


@dataclass
class RateLimiter:
    tokens: float
    last_refill_ms: int
    last_unknown_ms: int = 0


# ── Witness ─────────────────────────────────────────────────────────────────


class Witness:
    """In-memory witness. UDP loop calls `handle_packet(data, (ip, port))`
    which returns a list of (reply_bytes, (ip, port)) tuples to send back
    (usually 0 or 1 items)."""

    def __init__(
        self,
        witness_priv: bytes,
        witness_sender_id: Optional[bytes] = None,
        clock_ms=None,
    ):
        if len(witness_priv) != 32:
            raise ValueError("witness_priv must be 32 bytes")
        self.priv = witness_priv
        self.pub = crypto.x25519_pub_from_priv(witness_priv)
        self.sender_id = witness_sender_id or _default_witness_sender_id(self.pub)
        # start_ms = the monotonic clock reading at boot; uptime = now - start
        self._clock_ms = clock_ms or _monotonic_ms
        self.start_ms = self._clock_ms()
        self.clusters: dict[int, ClusterEntry] = {}          # cluster_slot → entry
        self.nodes: dict[bytes, NodeEntry] = {}              # sender_id → entry
        self._next_cluster_slot = 0
        self.rate_limits: dict[bytes, RateLimiter] = {}      # ipv4 bytes → RL

    # ── clock / helpers ──

    def now_ms(self) -> int:
        return self._clock_ms()

    def uptime_ms(self) -> int:
        return self.now_ms() - self.start_ms

    def _age_out_timeout_ms(self) -> int:
        n = len(self.nodes)
        for threshold, timeout in AGE_OUT_TIERS:
            if n <= threshold:
                return timeout
        return AGE_OUT_TIERS[-1][1]

    def _age_out(self) -> None:
        now = self.now_ms()
        timeout = self._age_out_timeout_ms()
        dead = [sid for sid, e in self.nodes.items()
                if now - e.last_rx_ms > timeout]
        for sid in dead:
            cs = self.nodes[sid].cluster_slot
            del self.nodes[sid]
            c = self.clusters.get(cs)
            if c is not None:
                c.num_nodes = max(0, c.num_nodes - 1)
                if c.num_nodes == 0:
                    del self.clusters[cs]
        if dead:
            log.info("aged out %d node(s)", len(dead))

    # ── rate limiter ──

    def _allow(self, ipv4: bytes, *, is_unknown_reply: bool = False) -> bool:
        now = self.now_ms()
        rl = self.rate_limits.get(ipv4)
        if rl is None:
            if len(self.rate_limits) >= MAX_TRACKED_IPS:
                # evict oldest
                oldest = min(self.rate_limits.items(), key=lambda kv: kv[1].last_refill_ms)
                del self.rate_limits[oldest[0]]
            rl = RateLimiter(tokens=float(RL_BURST), last_refill_ms=now)
            self.rate_limits[ipv4] = rl

        # refill
        elapsed = (now - rl.last_refill_ms) / 1000.0
        rl.tokens = min(RL_BURST, rl.tokens + elapsed * RL_RATE_PER_SEC)
        rl.last_refill_ms = now

        if is_unknown_reply:
            if now - rl.last_unknown_ms < int(1000 / RL_UNKNOWN_PER_SEC):
                return False
            rl.last_unknown_ms = now
            return True

        if rl.tokens < 1.0:
            return False
        rl.tokens -= 1.0
        return True

    # ── cluster / node table ──

    def _allocate_cluster_slot(self) -> Optional[int]:
        if len(self.clusters) >= MAX_CLUSTERS:
            return None
        for slot in range(MAX_CLUSTERS):
            if slot not in self.clusters:
                return slot
        return None

    def _install_cluster(self, cluster_key: bytes) -> Optional[ClusterEntry]:
        slot = self._allocate_cluster_slot()
        if slot is None:
            return None
        entry = ClusterEntry(
            cluster_slot=slot,
            cluster_key=cluster_key,
            bootstrapped_ms=self.now_ms(),
        )
        self.clusters[slot] = entry
        return entry

    def _tx_seq(self, peer_sender_id: bytes) -> int:
        node = self.nodes.get(peer_sender_id)
        if node is None:
            return self.now_ms()
        node.last_tx_sequence = max(self.now_ms(), node.last_tx_sequence + 1)
        return node.last_tx_sequence

    # ── dispatch entry point ──

    def handle_packet(self, data: bytes, src: tuple[str, int]) -> list[tuple[bytes, tuple[str, int]]]:
        """Process one incoming UDP datagram. Returns a list of replies
        (each is (bytes, (ip, port))). Always safe; exceptions are swallowed
        and turn into silent drops per spec §12."""
        if len(data) > MTU_CAP:
            return []
        ipv4 = proto.ipv4_to_bytes(src[0])
        # age out lazily on every packet (cheap)
        self._age_out()
        # rate limit (refill/consume happens here)
        if not self._allow(ipv4):
            return []

        try:
            hdr = Header.unpack(data)
        except ProtocolError as e:
            log.debug("bad header from %s: %s", src, e)
            return []
        if len(data) != HEADER_LEN + hdr.payload_len + _trailer_len(hdr.msg_type):
            return []

        if hdr.msg_type == MSG_BOOTSTRAP:
            return self._handle_bootstrap(data, hdr, ipv4, src)
        if hdr.msg_type == MSG_HEARTBEAT:
            return self._handle_heartbeat(data, hdr, ipv4, src)
        # STATUS / ACKs / UNKNOWN_SOURCE are witness→node only; drop.
        return []

    # ── bootstrap ──

    def _handle_bootstrap(self, data, hdr, ipv4, src):
        try:
            bs = proto.decode_bootstrap(data, self.priv)
        except (ProtocolError, AuthError) as e:
            log.debug("bootstrap decode failed from %s: %s", src, e)
            return []

        existing = self.nodes.get(bs.sender_id)
        if existing is not None:
            # sender already known in some cluster
            known_key = self.clusters[existing.cluster_slot].cluster_key
            if hmac.compare_digest(known_key, bs.cluster_key):
                # idempotent re-bootstrap: reset sequence tracking
                existing.last_rx_ms = self.now_ms()
                existing.last_rx_sequence = 0
                existing.last_tx_sequence = 0
                existing.sender_ipv4 = ipv4
                status = 0x01
            else:
                # sender_id claimed by someone else with a different cluster_key
                # Silently drop (don't leak that the cluster exists under a different key)
                log.warning("bootstrap sender_id collision for %s; dropped", bs.sender_id.hex())
                return []
        else:
            if len(self.nodes) >= MAX_NODES:
                log.warning("node table full, dropping bootstrap from %s", src)
                return []
            # find/allocate cluster
            # reuse a cluster if any existing node already has this cluster_key
            cluster = None
            for c in self.clusters.values():
                if hmac.compare_digest(c.cluster_key, bs.cluster_key):
                    cluster = c
                    break
            if cluster is None:
                cluster = self._install_cluster(bs.cluster_key)
                if cluster is None:
                    log.warning("cluster table full, dropping bootstrap")
                    return []
            self.nodes[bs.sender_id] = NodeEntry(
                sender_id=bs.sender_id,
                sender_ipv4=ipv4,
                cluster_slot=cluster.cluster_slot,
                last_rx_ms=self.now_ms(),
                last_rx_sequence=0,
                last_tx_sequence=0,
                payload=bs.init_payload[:proto.NODE_PAYLOAD_MAX],
            )
            cluster.num_nodes += 1
            status = 0x00

        node = self.nodes[bs.sender_id]
        cluster_key = self.clusters[node.cluster_slot].cluster_key
        ack = BootstrapAck(
            sender_id=self.sender_id,
            sequence=self._tx_seq(bs.sender_id),
            timestamp_ms=self.now_ms(),
            status=status,
            witness_uptime_ms=self.uptime_ms(),
        )
        return [(ack.encode(cluster_key), src)]

    # ── heartbeat ──

    def _handle_heartbeat(self, data, hdr, ipv4, src):
        node = self.nodes.get(hdr.sender_id)
        if node is None:
            if self._allow(ipv4, is_unknown_reply=True):
                us = UnknownSource(
                    sender_id=self.sender_id, sequence=self.now_ms(),
                    timestamp_ms=self.now_ms(),
                )
                return [(us.encode(), src)]
            return []

        cluster = self.clusters.get(node.cluster_slot)
        if cluster is None:
            # stale node entry without cluster; treat as unknown
            del self.nodes[hdr.sender_id]
            if self._allow(ipv4, is_unknown_reply=True):
                us = UnknownSource(
                    sender_id=self.sender_id, sequence=self.now_ms(),
                    timestamp_ms=self.now_ms(),
                )
                return [(us.encode(), src)]
            return []

        try:
            hb = proto.decode_heartbeat(data, cluster.cluster_key)
        except AuthError:
            # HMAC failed — maybe IP reused by a different cluster? Tell them
            # to re-bootstrap. (Rate-limited.)
            if self._allow(ipv4, is_unknown_reply=True):
                us = UnknownSource(
                    sender_id=self.sender_id, sequence=self.now_ms(),
                    timestamp_ms=self.now_ms(),
                )
                return [(us.encode(), src)]
            return []
        except ProtocolError:
            return []

        # Replay / sequence check
        if hb.sequence <= node.last_rx_sequence:
            return []
        node.last_rx_sequence = hb.sequence
        node.last_rx_ms = self.now_ms()
        node.sender_ipv4 = ipv4
        node.payload = hb.own_payload

        now_ms = self.now_ms()
        if hb.query_target_id == b"\x00" * 8:
            return [self._reply_status_list(hb, cluster, now_ms, src)]
        return [self._reply_status_detail(hb, cluster, now_ms, src)]

    def _reply_status_list(self, hb, cluster, now_ms, src):
        peers = [
            n for n in self.nodes.values()
            if n.cluster_slot == cluster.cluster_slot
        ]
        peers.sort(key=lambda n: now_ms - n.last_rx_ms)  # most recent first
        peers = peers[:LIST_MAX_ENTRIES]
        entries = tuple(
            ListEntry(
                peer_sender_id=p.sender_id,
                peer_ipv4=p.sender_ipv4,
                last_seen_seconds=min(0xFFFFFFFF, (now_ms - p.last_rx_ms) // 1000),
            )
            for p in peers
        )
        sl = StatusList(
            sender_id=self.sender_id,
            sequence=self._tx_seq(hb.sender_id),
            timestamp_ms=now_ms,
            witness_uptime_ms=self.uptime_ms(),
            entries=entries,
        )
        return (sl.encode(cluster.cluster_key), src)

    def _reply_status_detail(self, hb, cluster, now_ms, src):
        target_id = hb.query_target_id
        target = self.nodes.get(target_id)
        if target is None or target.cluster_slot != cluster.cluster_slot:
            sd = StatusDetail(
                sender_id=self.sender_id,
                sequence=self._tx_seq(hb.sender_id),
                timestamp_ms=now_ms,
                witness_uptime_ms=self.uptime_ms(),
                target_sender_id=target_id,
                status=0x01,
            )
        else:
            sd = StatusDetail(
                sender_id=self.sender_id,
                sequence=self._tx_seq(hb.sender_id),
                timestamp_ms=now_ms,
                witness_uptime_ms=self.uptime_ms(),
                target_sender_id=target_id,
                status=0x00,
                peer_ipv4=target.sender_ipv4,
                last_seen_seconds=min(0xFFFFFFFF, (now_ms - target.last_rx_ms) // 1000),
                peer_payload=target.payload,
            )
        return (sd.encode(cluster.cluster_key), src)


def _trailer_len(msg_type: int) -> int:
    if msg_type in proto.HMAC_MSG_TYPES:
        return HMAC_LEN
    return 0


def _monotonic_ms() -> int:
    return time.monotonic_ns() // 1_000_000


def _default_witness_sender_id(pub: bytes) -> bytes:
    return hashlib.sha256(pub).digest()[:8]


# ── UDP loop ───────────────────────────────────────────────────────────────


def run_forever(witness: Witness, bind: str = "0.0.0.0",
                port: int = 12321) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind, port))
    log.info("witness listening on %s:%d (pub=%s)",
             bind, port, witness.pub.hex())
    while True:
        try:
            data, src = sock.recvfrom(MTU_CAP + 64)
        except (BlockingIOError, InterruptedError):
            continue
        try:
            for reply, dst in witness.handle_packet(data, src):
                sock.sendto(reply, dst)
        except Exception:
            log.exception("while handling packet from %s", src)


# ── Persistent key file ────────────────────────────────────────────────────


def load_or_generate_priv(path: Path) -> bytes:
    """Load the X25519 privkey from `path`, generating it on first run.
    Writes with 0600 mode. Returns 32 raw bytes."""
    if path.exists():
        data = path.read_bytes()
        if len(data) != 32:
            raise ValueError(f"{path}: expected 32 raw bytes, got {len(data)}")
        return data
    path.parent.mkdir(parents=True, exist_ok=True)
    priv, _ = crypto.x25519_generate()
    # write with 0600
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, priv)
    finally:
        os.close(fd)
    return priv
