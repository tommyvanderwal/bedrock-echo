"""Stateful Bedrock Echo witness — v1 reference implementation.

Pure Python. RAM-only state. The UDP loop is a plain blocking socket.
The packet-handler `handle_packet(data, (ip, port))` is pure logic so
unit tests can drive it without sockets.

Implements PROTOCOL.md plus the witness-side behavior described in
docs/witness-implementation.md:
  - IP-first lookup with sender_id fallback
  - New-node-join scan (try AEAD against all known cluster_keys)
  - Per-cluster wall-clock offset (no NTP required)
  - Strict-monotonic last_rx_timestamp / last_tx_timestamp per node/cluster
  - Age-out tiers (72h / 4h / 5min)
  - Per-IP rate limiting + 1/s/IP cap on UNKNOWN_SOURCE replies
"""
from __future__ import annotations

import logging
import os
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidTag

from . import proto, crypto

log = logging.getLogger("echo.witness")


# ── Sizing (reference impl; small profile, plenty for tests + dev) ───────

MAX_NODES = 64
MAX_CLUSTERS = 32
MAX_TRACKED_IPS = 128

# Token bucket (PROTOCOL.md §11)
RL_RATE_PER_SEC = 10
RL_BURST = 20
RL_UNKNOWN_PER_SEC = 1

# Age-out tiers (PROTOCOL.md §10): (threshold_inclusive, timeout_ms)
AGE_OUT_TIERS = (
    (int(MAX_NODES * 0.80), 72 * 3600 * 1000),   # 0–80%: 72h
    (int(MAX_NODES * 0.90), 4 * 3600 * 1000),    # 80–90%: 4h
    (MAX_NODES, 5 * 60 * 1000),                  # >90%: 5min
)

# Per-cluster offset adaptation bounds (PROTOCOL.md §6.2)
MAX_BACKWARD_JUMP_MS = 1000     # reject packets > 1 s behind cluster frame
MAX_BACKWARD_STEP_MS = 10       # adapt offset backward at most 10 ms/packet


# ── State dataclasses ────────────────────────────────────────────────────


@dataclass
class ClusterEntry:
    cluster_slot: int
    cluster_key: bytes
    bootstrapped_ms: int       # witness uptime when this cluster was created
    num_nodes: int = 0
    cluster_offset: int = 0    # cluster wall-clock-ms = uptime + cluster_offset
    last_tx_timestamp: int = 0 # strict-monotonic outgoing timestamp_ms in cluster frame


@dataclass
class NodeEntry:
    sender_id: int
    sender_ipv4: bytes         # 4 bytes
    sender_src_port: int
    cluster_slot: int
    last_rx_ms: int            # witness uptime when last accepted packet arrived
    last_rx_timestamp: int     # cluster-frame timestamp_ms of last accepted pkt
    payload: bytes = b""       # 0..1152 bytes, multiple of 32


@dataclass
class RateLimiter:
    tokens: float
    last_refill_ms: int
    last_unknown_ms: int = 0


# ── Witness ──────────────────────────────────────────────────────────────


class Witness:
    """In-memory witness with RAM-only state.

    Driving from a UDP loop:
        for reply, dst in witness.handle_packet(data, src):
            sock.sendto(reply, dst)

    Driving from tests:
        feed packets one at a time, observe state, observe replies.
    """

    def __init__(
        self,
        witness_priv: bytes,
        clock_ms=None,
    ):
        if len(witness_priv) != 32:
            raise ValueError("witness_priv must be 32 bytes")
        self.priv = witness_priv
        self.pub = crypto.x25519_pub_from_priv(witness_priv)
        self._clock_ms = clock_ms or _monotonic_ms
        self.start_ms = self._clock_ms()
        # Use lists for predictable iteration; fine for the reference impl.
        self.clusters: dict[int, ClusterEntry] = {}        # slot → entry
        self.nodes: list[NodeEntry] = []                   # may have multiple entries with same sender_id
        self._next_cluster_slot = 0
        self.rate_limits: dict[bytes, RateLimiter] = {}    # ipv4 → RL

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
        survivors: list[NodeEntry] = []
        evicted = 0
        for n in self.nodes:
            if now - n.last_rx_ms > timeout:
                evicted += 1
                cluster = self.clusters.get(n.cluster_slot)
                if cluster is not None:
                    cluster.num_nodes = max(0, cluster.num_nodes - 1)
                    if cluster.num_nodes == 0:
                        del self.clusters[n.cluster_slot]
            else:
                survivors.append(n)
        if evicted:
            self.nodes = survivors
            log.info("aged out %d node(s)", evicted)

    # ── rate limiter ──

    def _allow(self, ipv4: bytes, *, is_unknown_reply: bool = False) -> bool:
        now = self.now_ms()
        rl = self.rate_limits.get(ipv4)
        if rl is None:
            if len(self.rate_limits) >= MAX_TRACKED_IPS:
                oldest = min(self.rate_limits.items(),
                             key=lambda kv: kv[1].last_refill_ms)
                del self.rate_limits[oldest[0]]
            rl = RateLimiter(tokens=float(RL_BURST), last_refill_ms=now)
            self.rate_limits[ipv4] = rl

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

    # ── cluster table ──

    def _allocate_cluster_slot(self) -> Optional[int]:
        if len(self.clusters) >= MAX_CLUSTERS:
            return None
        for slot in range(MAX_CLUSTERS):
            if slot not in self.clusters:
                return slot
        return None

    def _find_cluster_by_key(self, cluster_key: bytes) -> Optional[ClusterEntry]:
        for c in self.clusters.values():
            if c.cluster_key == cluster_key:
                return c
        return None

    def _install_cluster(self, cluster_key: bytes, seed_timestamp: int) -> Optional[ClusterEntry]:
        slot = self._allocate_cluster_slot()
        if slot is None:
            return None
        offset = seed_timestamp - self.uptime_ms()
        entry = ClusterEntry(
            cluster_slot=slot,
            cluster_key=cluster_key,
            bootstrapped_ms=self.now_ms(),
            num_nodes=0,
            cluster_offset=offset,
            last_tx_timestamp=0,
        )
        self.clusters[slot] = entry
        return entry

    def _adapt_cluster_offset(self, cluster: ClusterEntry, pkt_ts: int) -> bool:
        """Apply asymmetric adaptation rule. Returns False if packet should
        be dropped (too far behind cluster frame)."""
        expected = self.uptime_ms() + cluster.cluster_offset
        delta = pkt_ts - expected
        if delta > 0:
            cluster.cluster_offset += delta            # forward freely
        elif delta > -MAX_BACKWARD_JUMP_MS:
            step = max(delta, -MAX_BACKWARD_STEP_MS)
            cluster.cluster_offset += step             # bounded backward
        else:
            return False                                # too far behind
        return True

    def _next_tx_timestamp(self, cluster: ClusterEntry) -> int:
        ts = max(self.uptime_ms() + cluster.cluster_offset,
                 cluster.last_tx_timestamp + 1)
        cluster.last_tx_timestamp = ts
        return ts

    # ── node lookup ──

    def _find_nodes_by_ip_and_sender(self, ipv4: bytes, sid: int) -> list[NodeEntry]:
        return [n for n in self.nodes
                if n.sender_ipv4 == ipv4 and n.sender_id == sid]

    def _find_nodes_by_sender(self, sid: int) -> list[NodeEntry]:
        return [n for n in self.nodes if n.sender_id == sid]

    # ── dispatch entry point ──

    def handle_packet(self, data: bytes, src: tuple[str, int]) -> list[tuple[bytes, tuple[str, int]]]:
        """Process one incoming UDP datagram. Returns 0 or 1 reply tuples.
        Always safe; exceptions become silent drops per spec §12."""
        if len(data) > proto.MTU_CAP:
            return []
        try:
            ipv4 = proto.ipv4_to_bytes(src[0])
        except Exception:
            return []
        port = src[1]

        # Lazy age-out — cheap and runs on every packet.
        self._age_out()

        # Rate limit (refill/consume).
        if not self._allow(ipv4):
            return []

        # Parse header (bare minimum).
        try:
            hdr = proto.Header.unpack(data)
        except proto.ProtocolError as e:
            log.debug("bad header from %s: %s", src, e)
            return []

        # Dispatch by msg_type.
        if hdr.msg_type == proto.MSG_BOOTSTRAP:
            return self._handle_bootstrap(data, hdr, ipv4, port, src)
        if hdr.msg_type == proto.MSG_HEARTBEAT:
            return self._handle_heartbeat(data, hdr, ipv4, port, src)
        if hdr.msg_type == proto.MSG_DISCOVER:
            return self._handle_discover(data, hdr, ipv4, src)
        # STATUS, ACKs, UNKNOWN_SOURCE are witness→node only (or ignored here).
        return []

    # ── DISCOVER ──

    def _handle_discover(self, data, hdr, ipv4, src):
        if len(data) != proto.DISCOVER_LEN:
            return []
        if not self._allow(ipv4, is_unknown_reply=True):
            return []
        us = proto.UnknownSource(timestamp_ms=hdr.timestamp_ms or self.uptime_ms(),
                                 witness_pubkey=self.pub)
        return [(us.encode(), src)]

    # ── BOOTSTRAP ──

    def _handle_bootstrap(self, data, hdr, ipv4, port, src):
        try:
            bs = proto.decode_bootstrap(data, self.priv)
        except (proto.ProtocolError, proto.AuthError) as e:
            log.debug("bootstrap decode failed from %s: %s", src, e)
            return []

        # Look for an existing (sender_id, cluster_key) entry — idempotent path.
        existing = None
        for n in self._find_nodes_by_sender(bs.sender_id):
            cluster = self.clusters.get(n.cluster_slot)
            if cluster is not None and cluster.cluster_key == bs.cluster_key:
                existing = (n, cluster)
                break

        if existing is not None:
            node, cluster = existing
            # Idempotent re-bootstrap. Update IP, port, last_rx_ms.
            # Preserve last_rx_timestamp via MAX rule (anti-replay invariant).
            if not self._adapt_cluster_offset(cluster, bs.timestamp_ms):
                # Replay-equivalent — bootstrap timestamp behind cluster frame.
                return []
            node.sender_ipv4 = ipv4
            node.sender_src_port = port
            node.last_rx_ms = self.now_ms()
            node.last_rx_timestamp = max(node.last_rx_timestamp, bs.timestamp_ms)
            status = 0x01
        else:
            # Either: new cluster + first node, OR new node joining existing cluster.
            cluster = self._find_cluster_by_key(bs.cluster_key)
            if cluster is None:
                # Brand-new cluster.
                if len(self.nodes) >= MAX_NODES:
                    log.warning("node table full")
                    return []
                cluster = self._install_cluster(bs.cluster_key, bs.timestamp_ms)
                if cluster is None:
                    log.warning("cluster table full")
                    return []
            else:
                # New node joining existing cluster (uncommon — usually arrives
                # via HEARTBEAT, but BOOTSTRAP is a valid path too).
                if not self._adapt_cluster_offset(cluster, bs.timestamp_ms):
                    return []
            if len(self.nodes) >= MAX_NODES:
                return []
            self.nodes.append(NodeEntry(
                sender_id=bs.sender_id,
                sender_ipv4=ipv4,
                sender_src_port=port,
                cluster_slot=cluster.cluster_slot,
                last_rx_ms=self.now_ms(),
                last_rx_timestamp=bs.timestamp_ms,
                payload=b"",
            ))
            cluster.num_nodes += 1
            status = 0x00

        # Build BOOTSTRAP_ACK.
        ts_out = self._next_tx_timestamp(cluster)
        ack = proto.BootstrapAck(
            timestamp_ms=ts_out,
            status=status,
            witness_uptime_seconds=self.uptime_ms() // 1000,
        )
        return [(ack.encode(cluster.cluster_key), src)]

    # ── HEARTBEAT ──

    def _handle_heartbeat(self, data, hdr, ipv4, port, src):
        # Step 1: try IP+sender_id direct match.
        candidates = self._find_nodes_by_ip_and_sender(ipv4, hdr.sender_id)
        if not candidates:
            # IP changed? Try sender_id alone.
            candidates = self._find_nodes_by_sender(hdr.sender_id)

        # Try AEAD decrypt against each candidate's cluster_key.
        for node in candidates:
            cluster = self.clusters.get(node.cluster_slot)
            if cluster is None:
                continue
            try:
                hb = proto.decode_heartbeat(data, cluster.cluster_key)
            except proto.AuthError:
                continue
            except proto.ProtocolError:
                return []
            # Check anti-replay BEFORE updating state.
            if hb.timestamp_ms <= node.last_rx_timestamp:
                return []
            # Adapt cluster offset.
            if not self._adapt_cluster_offset(cluster, hb.timestamp_ms):
                return []
            # Update IP if it changed.
            if node.sender_ipv4 != ipv4:
                node.sender_ipv4 = ipv4
            node.sender_src_port = port
            node.last_rx_ms = self.now_ms()
            node.last_rx_timestamp = hb.timestamp_ms
            node.payload = hb.own_payload
            return [self._build_heartbeat_reply(hb, cluster, node, src)]

        # No matching candidate. Try new-node-join scan: AEAD against every cluster_key.
        for cluster in self.clusters.values():
            try:
                hb = proto.decode_heartbeat(data, cluster.cluster_key)
            except proto.AuthError:
                continue
            except proto.ProtocolError:
                return []
            # Found a cluster that authenticates this packet → new node.
            if len(self.nodes) >= MAX_NODES:
                return []
            if not self._adapt_cluster_offset(cluster, hb.timestamp_ms):
                return []
            new_node = NodeEntry(
                sender_id=hdr.sender_id,
                sender_ipv4=ipv4,
                sender_src_port=port,
                cluster_slot=cluster.cluster_slot,
                last_rx_ms=self.now_ms(),
                last_rx_timestamp=hb.timestamp_ms,
                payload=hb.own_payload,
            )
            self.nodes.append(new_node)
            cluster.num_nodes += 1
            return [self._build_heartbeat_reply(hb, cluster, new_node, src)]

        # Nothing matched anywhere. Reply UNKNOWN_SOURCE (rate-limited).
        if not self._allow(ipv4, is_unknown_reply=True):
            return []
        us = proto.UnknownSource(timestamp_ms=self.uptime_ms(), witness_pubkey=self.pub)
        return [(us.encode(), src)]

    def _build_heartbeat_reply(self, hb, cluster, sending_node, src):
        ts_out = self._next_tx_timestamp(cluster)
        if hb.query_target_id == proto.QUERY_LIST_SENTINEL:
            # STATUS_LIST: include all cluster members (incl. caller).
            peers = [n for n in self.nodes if n.cluster_slot == cluster.cluster_slot]
            peers.sort(key=lambda n: n.last_rx_timestamp, reverse=True)
            now_cluster_ts = self.uptime_ms() + cluster.cluster_offset
            entries = tuple(
                proto.ListEntry(
                    peer_sender_id=p.sender_id,
                    last_seen_ms=max(0, min(0xFFFFFFFF,
                                            now_cluster_ts - p.last_rx_timestamp)),
                )
                for p in peers[:proto.LIST_MAX_ENTRIES]
            )
            sl = proto.StatusList(
                timestamp_ms=ts_out,
                witness_uptime_seconds=self.uptime_ms() // 1000,
                entries=entries,
            )
            return (sl.encode(cluster.cluster_key), src)

        # STATUS_DETAIL for a specific target in this cluster.
        target_id = hb.query_target_id
        target = None
        for n in self.nodes:
            if n.cluster_slot == cluster.cluster_slot and n.sender_id == target_id:
                target = n
                break
        if target is None:
            sd = proto.StatusDetail(
                timestamp_ms=ts_out,
                witness_uptime_seconds=self.uptime_ms() // 1000,
                target_sender_id=target_id,
                found=False,
            )
        else:
            now_cluster_ts = self.uptime_ms() + cluster.cluster_offset
            sd = proto.StatusDetail(
                timestamp_ms=ts_out,
                witness_uptime_seconds=self.uptime_ms() // 1000,
                target_sender_id=target_id,
                found=True,
                peer_ipv4=target.sender_ipv4,
                peer_seen_ms_ago=max(0, min(0xFFFFFFFF,
                                            now_cluster_ts - target.last_rx_timestamp)),
                peer_payload=target.payload,
            )
        return (sd.encode(cluster.cluster_key), src)


# ── helpers ──────────────────────────────────────────────────────────────


def _monotonic_ms() -> int:
    return time.monotonic_ns() // 1_000_000


# ── UDP loop ─────────────────────────────────────────────────────────────


def run_forever(witness: Witness, bind: str = "0.0.0.0",
                port: int = 12321) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind, port))
    log.info("witness listening on %s:%d (pub=%s)",
             bind, port, witness.pub.hex())
    while True:
        try:
            data, src = sock.recvfrom(proto.MTU_CAP + 64)
        except (BlockingIOError, InterruptedError):
            continue
        try:
            for reply, dst in witness.handle_packet(data, src):
                sock.sendto(reply, dst)
        except Exception:
            log.exception("while handling packet from %s", src)


# ── Persistent X25519 key file ───────────────────────────────────────────


def load_or_generate_priv(path: Path) -> bytes:
    """Load the X25519 private key from `path`, generating + saving on
    first run. 32 raw bytes, 0600 permissions."""
    if path.exists():
        data = path.read_bytes()
        if len(data) != 32:
            raise ValueError(f"{path}: expected 32 raw bytes, got {len(data)}")
        return data
    path.parent.mkdir(parents=True, exist_ok=True)
    priv, _ = crypto.x25519_generate()
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, priv)
    finally:
        os.close(fd)
    return priv
