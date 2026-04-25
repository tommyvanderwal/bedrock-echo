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

# Fixed cookie secrets so test cookies are deterministic.
COOKIE_SECRET = bytes([0xCC] * 32)
PREV_COOKIE_SECRET = bytes([0xDD] * 32)


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
    w = witness.Witness(priv, clock_ms=clock,
                        cookie_secret=COOKIE_SECRET,
                        prev_cookie_secret=PREV_COOKIE_SECRET)
    return w, clock, w.pub


def cookie_for(ip_str: str, *, secret: bytes = COOKIE_SECRET) -> bytes:
    """Return the cookie a node at ip_str would have to echo to BOOTSTRAP."""
    return crypto.derive_cookie(secret, proto.ipv4_to_bytes(ip_str))


def encode_heartbeat(sender_id: int, ts: int, query: int, payload: bytes,
                     cluster_key: bytes) -> bytes:
    return proto.Heartbeat(
        sender_id=sender_id, timestamp_ms=ts,
        query_target_id=query, own_payload=payload,
    ).encode(cluster_key)


def encode_bootstrap(sender_id: int, ts: int, cluster_key: bytes,
                     w_pubkey: bytes, *, cookie: bytes | None = None,
                     src_ip: str = "192.168.1.10") -> bytes:
    """Encode a BOOTSTRAP. If cookie is None, derive the correct one for
    src_ip under the test's fixed cookie secret (cookie validation will
    succeed)."""
    eph_priv, _ = crypto.x25519_generate()
    if cookie is None:
        cookie = cookie_for(src_ip)
    return proto.Bootstrap(
        sender_id=sender_id, timestamp_ms=ts, cluster_key=cluster_key,
        cookie=cookie,
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
    pkt1 = encode_bootstrap(NODE_A, 1700_000_000_000, CK, pub,
                            src_ip="192.168.1.10")
    w.handle_packet(pkt1, ("192.168.1.10", 50000))
    clock.advance(1000)
    pkt2 = encode_bootstrap(NODE_A, 1700_000_001_000, CK2, pub,
                            src_ip="192.168.1.20")
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
    assert len(reply) == proto.INIT_LEN
    us = proto.decode_init(reply)
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


def test_new_node_via_heartbeat_alone_returns_init():
    """In v1 the new-node-join-via-HEARTBEAT scan has been removed.
    A new node's HEARTBEAT — even with a valid cluster_key — does NOT
    create a witness entry; the witness replies INIT and the node is
    expected to BOOTSTRAP."""
    w, clock, pub = make_witness()
    # Node A bootstraps to create the cluster
    w.handle_packet(encode_bootstrap(NODE_A, 1700_000_000_000, CK, pub,
                                     src_ip="192.168.1.10"),
                    ("192.168.1.10", 50000))
    clock.advance(1000)
    # Node B sends a HEARTBEAT directly, no BOOTSTRAP
    pkt = encode_heartbeat(NODE_B, 1700_000_001_000, 0xFF, b"", CK)
    replies = w.handle_packet(pkt, ("192.168.1.20", 50000))
    # Witness must NOT add B; it must reply INIT
    assert len(w.nodes) == 1  # only A
    assert len(replies) == 1
    init = proto.decode_init(replies[0][0])
    assert init.witness_pubkey == pub
    assert init.cookie == cookie_for("192.168.1.20")


def test_new_node_joins_via_bootstrap():
    """The supported v1 flow for a 2nd node: it BOOTSTRAPs into the
    existing cluster (cookie-validated), then HEARTBEATs."""
    w, clock, pub = make_witness()
    w.handle_packet(encode_bootstrap(NODE_A, 1700_000_000_000, CK, pub,
                                     src_ip="192.168.1.10"),
                    ("192.168.1.10", 50000))
    clock.advance(1000)
    # Node B BOOTSTRAPs (with cookie for its src_ip) into the existing cluster
    bs_b = encode_bootstrap(NODE_B, 1700_000_001_000, CK, pub,
                            src_ip="192.168.1.20")
    w.handle_packet(bs_b, ("192.168.1.20", 50000))
    assert len(w.nodes) == 2
    assert len(w.clusters) == 1  # both nodes share the same cluster
    # Now B HEARTBEATs and gets a STATUS_LIST including both
    clock.advance(100)
    hb = encode_heartbeat(NODE_B, 1700_000_001_100, 0xFF, b"", CK)
    r = w.handle_packet(hb, ("192.168.1.20", 50000))
    sl = proto.decode_status_list(r[0][0], CK)
    sender_ids = {e.peer_sender_id for e in sl.entries}
    assert sender_ids == {NODE_A, NODE_B}


def test_heartbeat_with_no_known_cluster_returns_init():
    """A node sending HEARTBEAT with a cluster_key the witness doesn't know
    gets INIT (with a fresh cookie for re-BOOTSTRAP)."""
    w, _, pub = make_witness()
    pkt = encode_heartbeat(NODE_A, 1700_000_000_000, 0xFF, b"", CK)
    replies = w.handle_packet(pkt, ("192.168.1.10", 50000))
    assert len(replies) == 1
    init = proto.decode_init(replies[0][0])
    assert init.witness_pubkey == pub
    assert init.cookie == cookie_for("192.168.1.10")


def test_heartbeat_from_new_ip_returns_init_not_silent_takeover():
    """v1 strict (src_ip, sender_id) match: a HEARTBEAT from a new IP
    for an existing sender_id does NOT silently update the stored IP.
    Witness replies INIT; node is expected to re-BOOTSTRAP."""
    w, clock, pub = make_witness()
    w.handle_packet(encode_bootstrap(NODE_A, 1700_000_000_000, CK, pub,
                                     src_ip="192.168.1.10"),
                    ("192.168.1.10", 50000))
    clock.advance(100)
    # Same sender_id from a different IP — must NOT silently take over.
    pkt = encode_heartbeat(NODE_A, 1700_000_000_100, 0xFF, b"", CK)
    replies = w.handle_packet(pkt, ("192.168.1.99", 50000))
    assert len(w.nodes) == 1
    # Stored IP unchanged (still .10)
    assert w.nodes[0].sender_ipv4 == proto.ipv4_to_bytes("192.168.1.10")
    # And the witness offered an INIT so the new IP can re-bootstrap
    assert len(replies) == 1
    proto.decode_init(replies[0][0])  # parses successfully


def test_heartbeat_ip_change_via_rebootstrap_updates_entry():
    """The supported recovery path for a DHCP renewal: re-BOOTSTRAP from
    the new IP. The existing (sender_id, cluster_key) entry is found and
    its sender_ipv4 is updated."""
    w, clock, pub = make_witness()
    w.handle_packet(encode_bootstrap(NODE_A, 1700_000_000_000, CK, pub,
                                     src_ip="192.168.1.10"),
                    ("192.168.1.10", 50000))
    clock.advance(100)
    # Re-BOOTSTRAP from the new IP (cookie derived for that IP)
    bs2 = encode_bootstrap(NODE_A, 1700_000_000_100, CK, pub,
                           src_ip="192.168.1.99")
    replies = w.handle_packet(bs2, ("192.168.1.99", 50000))
    assert len(w.nodes) == 1  # idempotent — one entry
    assert w.nodes[0].sender_ipv4 == proto.ipv4_to_bytes("192.168.1.99")
    ack = proto.decode_bootstrap_ack(replies[0][0], CK)
    assert ack.status == 0x01  # idempotent re-bootstrap


# ── DISCOVER path ─────────────────────────────────────────────────────────


def test_discover_returns_init_with_pubkey_and_cookie():
    w, _, pub = make_witness()
    d = proto.Discover(sender_id=NODE_A, timestamp_ms=1700_000_000_000)
    replies = w.handle_packet(d.encode(), ("192.168.1.10", 50000))
    assert len(replies) == 1
    init = proto.decode_init(replies[0][0])
    assert init.witness_pubkey == pub
    assert init.cookie == cookie_for("192.168.1.10")


def test_discover_request_reply_size_match():
    """Anti-amplification: DISCOVER (62 B) → INIT (62 B), 1.0× factor."""
    w, _, _ = make_witness()
    d = proto.Discover(sender_id=NODE_A, timestamp_ms=0)
    pkt = d.encode()
    replies = w.handle_packet(pkt, ("192.168.1.10", 50000))
    assert len(pkt) == 62 == len(replies[0][0])


def test_discover_does_not_create_node_entry():
    w, _, pub = make_witness()
    d = proto.Discover(sender_id=NODE_A, timestamp_ms=1700_000_000_000)
    w.handle_packet(d.encode(), ("192.168.1.10", 50000))
    assert len(w.nodes) == 0
    assert len(w.clusters) == 0


# ── Cookie validation ────────────────────────────────────────────────────


def test_bootstrap_with_bad_cookie_silently_dropped():
    """A BOOTSTRAP carrying a cookie that doesn't match the witness's
    current OR previous cookie secret must be silent-dropped before
    any AEAD/X25519 work."""
    w, _, pub = make_witness()
    bs_pkt = encode_bootstrap(NODE_A, 1700_000_000_000, CK, pub,
                              cookie=b"\xAA" * 16)  # wrong cookie
    replies = w.handle_packet(bs_pkt, ("192.168.1.10", 50000))
    assert replies == []
    assert len(w.nodes) == 0  # no entry created
    assert len(w.clusters) == 0


def test_bootstrap_with_previous_cookie_secret_accepted():
    """During the rotation grace window (~1 hour) the previous cookie
    secret is still valid. Tests the witness's validation against
    BOTH current and previous secrets."""
    w, _, pub = make_witness()
    # Pretend the node received an INIT under the PREVIOUS secret.
    prev_cookie = cookie_for("192.168.1.10", secret=PREV_COOKIE_SECRET)
    bs_pkt = encode_bootstrap(NODE_A, 1700_000_000_000, CK, pub,
                              cookie=prev_cookie)
    replies = w.handle_packet(bs_pkt, ("192.168.1.10", 50000))
    assert len(w.nodes) == 1
    assert len(replies) == 1
    proto.decode_bootstrap_ack(replies[0][0], CK)


def test_cookie_for_different_ip_is_rejected():
    """An attacker sniffing one node's cookie cannot reuse it from a
    different src_ip — the cookie binds to the IP."""
    w, _, pub = make_witness()
    # Cookie is computed for .10 but bootstrap arrives from .99
    spoofed_pkt = encode_bootstrap(NODE_A, 1700_000_000_000, CK, pub,
                                   cookie=cookie_for("192.168.1.10"))
    replies = w.handle_packet(spoofed_pkt, ("192.168.1.99", 50000))
    assert replies == []
    assert len(w.nodes) == 0


def test_cookie_rotation_after_one_hour():
    """After 1 hour of uptime, the witness rotates its cookie secret.
    The current secret becomes 'previous'; a fresh secret is generated."""
    w, clock, pub = make_witness()
    secret_before = w._cookie_current
    prev_before = w._cookie_previous
    # Advance just under the rotation window — no rotation yet.
    clock.advance(witness.COOKIE_SECRET_ROTATION_MS - 1)
    w.handle_packet(b"Echo\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                    ("192.168.1.10", 50000))  # any malformed packet triggers
    assert w._cookie_current == secret_before  # still no rotation
    # Advance past the rotation window.
    clock.advance(2)
    # Trigger the lazy rotation via a normal call.
    d = proto.Discover(sender_id=NODE_A, timestamp_ms=0)
    w.handle_packet(d.encode(), ("192.168.1.11", 50000))
    assert w._cookie_previous == secret_before  # old current → previous
    assert w._cookie_current != secret_before   # new current generated
    assert w._cookie_current != prev_before     # not the same as old previous


# ── Rate limiting ─────────────────────────────────────────────────────────


def test_init_rate_limited_per_ip():
    w, clock, pub = make_witness()
    src = ("192.168.1.10", 50000)
    # First INIT-triggering HEARTBEAT
    pkt1 = encode_heartbeat(NODE_A, 1700_000_000_000, 0xFF, b"", CK)
    r1 = w.handle_packet(pkt1, src)
    assert len(r1) == 1
    # Second one within 1s — should be rate-limited (no INIT reply)
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
    w.handle_packet(encode_bootstrap(NODE_A, 1700_000_000_000, CK, pub,
                                     src_ip="192.168.1.10"),
                    ("192.168.1.10", 50000))
    clock.advance(100)
    # Cluster 2 (CK2), node A — same sender_id, different cluster_key
    w.handle_packet(encode_bootstrap(NODE_A, 1700_000_000_100, CK2, pub,
                                     src_ip="192.168.1.20"),
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


# ── DISCOVER + INIT + cookie-validated BOOTSTRAP flow ─────────────────────


def test_full_discover_bootstrap_heartbeat_flow():
    w, clock, pub = make_witness()
    src = ("192.168.1.10", 50000)

    # 1. Node DISCOVER → INIT with pubkey + cookie
    d = proto.Discover(sender_id=NODE_A, timestamp_ms=1700_000_000_000)
    r1 = w.handle_packet(d.encode(), src)
    init = proto.decode_init(r1[0][0])
    assert init.witness_pubkey == pub
    assert len(init.cookie) == 16

    # 2. Node BOOTSTRAP carrying the witness's cookie → ACK
    clock.advance(100)
    bs_pkt = encode_bootstrap(NODE_A, 1700_000_000_100, CK, init.witness_pubkey,
                              cookie=init.cookie, src_ip="192.168.1.10")
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
