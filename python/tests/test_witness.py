"""Witness state machine tests — unit-level, no sockets.

Drive the witness via handle_packet() with hand-crafted packets and
assert on observable state and replies.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from echo import proto, crypto, witness  # noqa: E402


CK = bytes(range(0x10, 0x30))
CK2 = bytes([0x99] * 32)
NODE_A = 0x01
NODE_B = 0x02


class FakeClock:
    """Programmable clock for deterministic testing."""

    def __init__(self, t0: int = 0):
        self._now = t0

    def __call__(self) -> int:
        return self._now

    def advance(self, ms: int) -> None:
        self._now += ms


def make_witness(*, t0: int = 100_000_000_000) -> tuple[witness.Witness, FakeClock, bytes]:
    """Create a witness with a fixed key and a controllable clock.
    Returns (witness, clock, witness_pubkey)."""
    priv = bytes([0xAA] * 32)
    clock = FakeClock(t0)
    w = witness.Witness(priv, clock_ms=clock)
    return w, clock, w.pub


def encode_heartbeat(sender_id: int, ts: int, query: int, payload: bytes,
                     cluster_key: bytes) -> bytes:
    return proto.Heartbeat(
        sender_id=sender_id, timestamp_ms=ts,
        query_target_id=query, own_payload=payload,
    ).encode(cluster_key)


def encode_bootstrap(sender_id: int, ts: int, cluster_key: bytes,
                     w_pubkey: bytes) -> bytes:
    eph_priv, _ = crypto.x25519_generate()
    return proto.Bootstrap(
        sender_id=sender_id, timestamp_ms=ts, cluster_key=cluster_key,
    ).encode(w_pubkey, eph_priv)


# ── BOOTSTRAP path ────────────────────────────────────────────────────────


def test_bootstrap_creates_cluster_and_node():
    w, clock, pub = make_witness()
    pkt = encode_bootstrap(NODE_A, 1700_000_000_000, CK, pub)
    replies = w.handle_packet(pkt, ("192.168.1.10", 50000))
    assert len(replies) == 1
    assert len(w.clusters) == 1
    assert len(w.nodes) == 1
    assert w.nodes[0].sender_id == NODE_A
    # Reply is BOOTSTRAP_ACK status=0x00 (new)
    reply_bytes, dst = replies[0]
    ack = proto.decode_bootstrap_ack(reply_bytes, CK)
    assert ack.status == 0x00
    assert dst == ("192.168.1.10", 50000)


def test_idempotent_rebootstrap_returns_status_01():
    w, clock, pub = make_witness()
    pkt1 = encode_bootstrap(NODE_A, 1700_000_000_000, CK, pub)
    w.handle_packet(pkt1, ("192.168.1.10", 50000))
    clock.advance(1000)
    pkt2 = encode_bootstrap(NODE_A, 1700_000_001_000, CK, pub)
    replies = w.handle_packet(pkt2, ("192.168.1.10", 50000))
    assert len(w.nodes) == 1  # idempotent — still one node
    assert len(w.clusters) == 1
    ack = proto.decode_bootstrap_ack(replies[0][0], CK)
    assert ack.status == 0x01


def test_bootstrap_with_different_cluster_key_creates_second_entry():
    """Collision-resolution: same sender_id, different cluster_key →
    two coexisting node entries."""
    w, clock, pub = make_witness()
    pkt1 = encode_bootstrap(NODE_A, 1700_000_000_000, CK, pub)
    w.handle_packet(pkt1, ("192.168.1.10", 50000))
    clock.advance(1000)
    pkt2 = encode_bootstrap(NODE_A, 1700_000_001_000, CK2, pub)
    replies = w.handle_packet(pkt2, ("192.168.1.20", 50000))
    assert len(w.nodes) == 2  # both coexist
    assert len(w.clusters) == 2
    # Second one is "new" status
    ack = proto.decode_bootstrap_ack(replies[0][0], CK2)
    assert ack.status == 0x00


def test_bad_aead_silently_dropped():
    w, _, _ = make_witness()
    # Forge a "BOOTSTRAP" with garbage that won't decrypt.
    fake = b"Echo" + bytes([0x20, NODE_A]) + (1700_000_000_000).to_bytes(8, "big") \
           + b"\x00" * (32 + 32 + 16)
    replies = w.handle_packet(fake, ("192.168.1.99", 1000))
    assert replies == []
    assert len(w.nodes) == 0


# ── HEARTBEAT path ────────────────────────────────────────────────────────


def test_heartbeat_unknown_sender_returns_unknown_source():
    w, _, pub = make_witness()
    pkt = encode_heartbeat(NODE_A, 1700_000_000_000, 0xFF, b"", CK)
    replies = w.handle_packet(pkt, ("192.168.1.10", 50000))
    assert len(replies) == 1
    reply, _ = replies[0]
    assert len(reply) == proto.UNKNOWN_SOURCE_LEN
    us = proto.decode_unknown_source(reply)
    assert us.witness_pubkey == pub


def test_heartbeat_after_bootstrap_returns_status_list():
    w, clock, pub = make_witness()
    w.handle_packet(encode_bootstrap(NODE_A, 1700_000_000_000, CK, pub),
                    ("192.168.1.10", 50000))
    clock.advance(1000)
    pkt = encode_heartbeat(NODE_A, 1700_000_001_000, 0xFF, b"", CK)
    replies = w.handle_packet(pkt, ("192.168.1.10", 50000))
    assert len(replies) == 1
    sl = proto.decode_status_list(replies[0][0], CK)
    assert len(sl.entries) == 1  # caller's own entry included
    assert sl.entries[0].peer_sender_id == NODE_A


def test_heartbeat_detail_query_for_unknown_peer():
    w, clock, pub = make_witness()
    w.handle_packet(encode_bootstrap(NODE_A, 1700_000_000_000, CK, pub),
                    ("192.168.1.10", 50000))
    clock.advance(100)
    pkt = encode_heartbeat(NODE_A, 1700_000_000_100, NODE_B, b"", CK)
    replies = w.handle_packet(pkt, ("192.168.1.10", 50000))
    sd = proto.decode_status_detail(replies[0][0], CK)
    assert sd.found is False
    assert sd.target_sender_id == NODE_B


def test_heartbeat_self_query_returns_caller_state():
    w, clock, pub = make_witness()
    w.handle_packet(encode_bootstrap(NODE_A, 1700_000_000_000, CK, pub),
                    ("192.168.1.10", 50000))
    clock.advance(100)
    payload = b"intent=promote" + b"\x00" * (32 - 14)
    pkt = encode_heartbeat(NODE_A, 1700_000_000_100, NODE_A, payload, CK)
    replies = w.handle_packet(pkt, ("192.168.1.10", 50000))
    sd = proto.decode_status_detail(replies[0][0], CK)
    assert sd.found is True
    assert sd.target_sender_id == NODE_A
    assert sd.peer_payload == payload  # exactly what we just sent


def test_heartbeat_anti_replay():
    w, clock, pub = make_witness()
    w.handle_packet(encode_bootstrap(NODE_A, 1700_000_000_000, CK, pub),
                    ("192.168.1.10", 50000))
    clock.advance(100)
    # First HB at ts=1700000000100
    pkt1 = encode_heartbeat(NODE_A, 1700_000_000_100, 0xFF, b"", CK)
    r1 = w.handle_packet(pkt1, ("192.168.1.10", 50000))
    assert len(r1) == 1
    # Replay the SAME packet → should be silently dropped
    r2 = w.handle_packet(pkt1, ("192.168.1.10", 50000))
    assert r2 == []
    # Older timestamp → also dropped
    pkt_old = encode_heartbeat(NODE_A, 1700_000_000_050, 0xFF, b"", CK)
    r3 = w.handle_packet(pkt_old, ("192.168.1.10", 50000))
    assert r3 == []
    # Newer timestamp → accepted
    pkt_new = encode_heartbeat(NODE_A, 1700_000_000_200, 0xFF, b"", CK)
    r4 = w.handle_packet(pkt_new, ("192.168.1.10", 50000))
    assert len(r4) == 1


def test_new_node_join_existing_cluster_via_heartbeat():
    """Subsequent nodes don't BOOTSTRAP — they HEARTBEAT, and the witness
    auto-creates their entry via the new-node-join scan."""
    w, clock, pub = make_witness()
    # Node A bootstraps to create the cluster
    w.handle_packet(encode_bootstrap(NODE_A, 1700_000_000_000, CK, pub),
                    ("192.168.1.10", 50000))
    clock.advance(1000)
    # Node B sends a HEARTBEAT directly, no BOOTSTRAP
    pkt = encode_heartbeat(NODE_B, 1700_000_001_000, 0xFF, b"", CK)
    replies = w.handle_packet(pkt, ("192.168.1.20", 50000))
    # Witness should have added B and replied with STATUS_LIST
    assert len(w.nodes) == 2
    sl = proto.decode_status_list(replies[0][0], CK)
    sender_ids = {e.peer_sender_id for e in sl.entries}
    assert sender_ids == {NODE_A, NODE_B}


def test_heartbeat_with_no_known_cluster_returns_unknown_source():
    """A node sending HEARTBEAT with a cluster_key the witness doesn't know
    gets UNKNOWN_SOURCE."""
    w, _, pub = make_witness()
    pkt = encode_heartbeat(NODE_A, 1700_000_000_000, 0xFF, b"", CK)
    replies = w.handle_packet(pkt, ("192.168.1.10", 50000))
    assert len(replies) == 1
    us = proto.decode_unknown_source(replies[0][0])
    assert us.witness_pubkey == pub


def test_heartbeat_ip_change_updates_entry():
    w, clock, pub = make_witness()
    w.handle_packet(encode_bootstrap(NODE_A, 1700_000_000_000, CK, pub),
                    ("192.168.1.10", 50000))
    clock.advance(100)
    # Same node from a different IP (DHCP renewal)
    pkt = encode_heartbeat(NODE_A, 1700_000_000_100, 0xFF, b"", CK)
    w.handle_packet(pkt, ("192.168.1.99", 50000))
    assert len(w.nodes) == 1
    assert w.nodes[0].sender_ipv4 == proto.ipv4_to_bytes("192.168.1.99")


# ── DISCOVER path ─────────────────────────────────────────────────────────


def test_discover_returns_unknown_source_with_pubkey():
    w, _, pub = make_witness()
    d = proto.Discover(sender_id=NODE_A, timestamp_ms=1700_000_000_000)
    replies = w.handle_packet(d.encode(), ("192.168.1.10", 50000))
    assert len(replies) == 1
    us = proto.decode_unknown_source(replies[0][0])
    assert us.witness_pubkey == pub


def test_discover_does_not_create_node_entry():
    w, _, pub = make_witness()
    d = proto.Discover(sender_id=NODE_A, timestamp_ms=1700_000_000_000)
    w.handle_packet(d.encode(), ("192.168.1.10", 50000))
    assert len(w.nodes) == 0
    assert len(w.clusters) == 0


# ── Rate limiting ─────────────────────────────────────────────────────────


def test_unknown_source_rate_limited_per_ip():
    w, clock, pub = make_witness()
    src = ("192.168.1.10", 50000)
    # First UNKNOWN_SOURCE-triggering HEARTBEAT
    pkt1 = encode_heartbeat(NODE_A, 1700_000_000_000, 0xFF, b"", CK)
    r1 = w.handle_packet(pkt1, src)
    assert len(r1) == 1
    # Second one within 1s — should be rate-limited (no UNKNOWN_SOURCE reply)
    clock.advance(100)
    pkt2 = encode_heartbeat(NODE_A, 1700_000_000_001, 0xFF, b"", CK)
    r2 = w.handle_packet(pkt2, src)
    assert r2 == []
    # After 1+ s — rate limit refreshes
    clock.advance(1500)
    pkt3 = encode_heartbeat(NODE_A, 1700_000_000_002, 0xFF, b"", CK)
    r3 = w.handle_packet(pkt3, src)
    assert len(r3) == 1


# ── Cluster offset / per-cluster timestamp ────────────────────────────────


def test_cluster_offset_seeded_on_bootstrap():
    w, clock, pub = make_witness(t0=100_000)  # uptime_ms starts at 0
    pkt_ts = 1700_000_000_000
    w.handle_packet(encode_bootstrap(NODE_A, pkt_ts, CK, pub),
                    ("192.168.1.10", 50000))
    cluster = list(w.clusters.values())[0]
    # cluster_offset = pkt_ts - witness.uptime_ms (uptime is 0 initially)
    assert cluster.cluster_offset == pkt_ts


def test_per_cluster_tx_timestamp_strictly_monotonic():
    """Witness's outgoing timestamps for the same cluster must be strictly
    increasing across replies."""
    w, clock, pub = make_witness()
    w.handle_packet(encode_bootstrap(NODE_A, 1700_000_000_000, CK, pub),
                    ("192.168.1.10", 50000))
    cluster = list(w.clusters.values())[0]
    last_tx = cluster.last_tx_timestamp

    # Drive several heartbeats; each reply must advance the cluster's tx_ts
    for i in range(1, 5):
        clock.advance(1)  # 1 ms each
        pkt = encode_heartbeat(NODE_A, 1700_000_000_000 + i, 0xFF, b"", CK)
        w.handle_packet(pkt, ("192.168.1.10", 50000))
        assert cluster.last_tx_timestamp > last_tx
        last_tx = cluster.last_tx_timestamp


# ── Cross-cluster isolation ───────────────────────────────────────────────


def test_two_clusters_with_same_sender_id_isolated():
    w, clock, pub = make_witness()
    # Cluster 1 (CK), node A
    w.handle_packet(encode_bootstrap(NODE_A, 1700_000_000_000, CK, pub),
                    ("192.168.1.10", 50000))
    clock.advance(100)
    # Cluster 2 (CK2), node A — same sender_id, different cluster_key
    w.handle_packet(encode_bootstrap(NODE_A, 1700_000_000_100, CK2, pub),
                    ("192.168.1.20", 50000))
    assert len(w.clusters) == 2
    assert len(w.nodes) == 2
    # Cluster 1's heartbeat with CK should reach cluster 1's node
    clock.advance(100)
    pkt1 = encode_heartbeat(NODE_A, 1700_000_000_200, 0xFF, b"\x11" * 32, CK)
    r1 = w.handle_packet(pkt1, ("192.168.1.10", 50000))
    sl1 = proto.decode_status_list(r1[0][0], CK)
    assert len(sl1.entries) == 1
    # Cluster 2's heartbeat with CK2 should reach cluster 2's node, not see cluster 1
    clock.advance(100)
    pkt2 = encode_heartbeat(NODE_A, 1700_000_000_300, 0xFF, b"\x22" * 32, CK2)
    r2 = w.handle_packet(pkt2, ("192.168.1.20", 50000))
    sl2 = proto.decode_status_list(r2[0][0], CK2)
    assert len(sl2.entries) == 1


# ── DISCOVER + UNKNOWN_SOURCE flow ────────────────────────────────────────


def test_full_discover_bootstrap_heartbeat_flow():
    w, clock, pub = make_witness()
    src = ("192.168.1.10", 50000)

    # 1. Node DISCOVER → UNKNOWN_SOURCE with pubkey
    d = proto.Discover(sender_id=NODE_A, timestamp_ms=1700_000_000_000)
    r1 = w.handle_packet(d.encode(), src)
    us = proto.decode_unknown_source(r1[0][0])
    assert us.witness_pubkey == pub

    # 2. Node BOOTSTRAP using the discovered pubkey → ACK
    clock.advance(100)
    bs_pkt = encode_bootstrap(NODE_A, 1700_000_000_100, CK, us.witness_pubkey)
    r2 = w.handle_packet(bs_pkt, src)
    ack = proto.decode_bootstrap_ack(r2[0][0], CK)
    assert ack.status == 0x00  # new

    # 3. Node HEARTBEAT → STATUS_LIST
    clock.advance(100)
    hb_pkt = encode_heartbeat(NODE_A, 1700_000_000_200, 0xFF, b"\x01" * 32, CK)
    r3 = w.handle_packet(hb_pkt, src)
    sl = proto.decode_status_list(r3[0][0], CK)
    assert len(sl.entries) == 1
    assert sl.entries[0].peer_sender_id == NODE_A
