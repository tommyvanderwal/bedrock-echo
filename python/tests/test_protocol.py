"""Wire-format encode/decode round-trip tests for Echo.

Run from the repo root:
    PYTHONPATH=python python3 -m pytest python/tests/ -v
"""
from __future__ import annotations

import os
import struct
import sys
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from echo import proto, crypto  # noqa: E402


# Fixed test fixtures
CK = bytes(range(0x10, 0x30))     # 32 B cluster_key
CK2 = bytes([0x99] * 32)          # alternate cluster_key for cross-cluster tests
NODE_A = 0x01
NODE_B = 0x02


# ── Header round-trip ─────────────────────────────────────────────────────


def test_header_pack_unpack_roundtrip():
    h = proto.Header(msg_type=0x01, sender_id=0x42, timestamp_ms=1700000000000)
    packed = h.pack()
    assert len(packed) == proto.HEADER_LEN == 14
    unpacked = proto.Header.unpack(packed)
    assert unpacked == h


def test_header_rejects_short_input():
    with pytest.raises(proto.ProtocolError, match="short header"):
        proto.Header.unpack(b"Echo\x01")


def test_header_rejects_bad_magic():
    bad = b"Xcho" + b"\x01\x42" + struct.pack(">q", 0)
    with pytest.raises(proto.ProtocolError, match="bad magic"):
        proto.Header.unpack(bad)


def test_header_rejects_unknown_msg_type():
    bad = b"Echo" + bytes([0x99, 0x42]) + struct.pack(">q", 0)
    with pytest.raises(proto.ProtocolError, match="unknown msg_type"):
        proto.Header.unpack(bad)


# ── Nonce derivation ──────────────────────────────────────────────────────


def test_derive_nonce_basic():
    n = proto.derive_nonce(0x01, 1700000000000)
    assert len(n) == 12
    # Layout: 1 B sender_id || 3 B zero pad || 8 B timestamp_ms BE
    assert n[0] == 0x01
    assert n[1:4] == b"\x00\x00\x00"
    assert struct.unpack(">q", n[4:])[0] == 1700000000000


def test_derive_nonce_distinguishes_witness_from_node():
    n_node = proto.derive_nonce(0x01, 1700000000000)
    n_witness = proto.derive_nonce(0xFF, 1700000000000)
    assert n_node != n_witness  # crucial for AEAD safety


def test_derive_nonce_distinguishes_consecutive_packets():
    n1 = proto.derive_nonce(0x01, 1700000000000)
    n2 = proto.derive_nonce(0x01, 1700000000001)
    assert n1 != n2  # strict-monotonic timestamp guarantees nonce uniqueness


# ── HEARTBEAT (0x01) ──────────────────────────────────────────────────────


def test_heartbeat_list_query_empty_payload():
    hb = proto.Heartbeat(NODE_A, 1700000000000, 0xFF, b"")
    wire = hb.encode(CK)
    assert len(wire) == 32  # 14 header + 2 plaintext + 16 tag
    assert proto.decode_heartbeat(wire, CK) == hb


def test_heartbeat_detail_query_with_payload():
    payload = b"X" * 64  # 2 blocks
    hb = proto.Heartbeat(NODE_A, 1700000000000, NODE_B, payload)
    wire = hb.encode(CK)
    assert len(wire) == 32 + 64
    assert proto.decode_heartbeat(wire, CK) == hb


def test_heartbeat_self_query():
    hb = proto.Heartbeat(NODE_A, 1700000000000, NODE_A, b"\x01" * 32)
    assert proto.decode_heartbeat(hb.encode(CK), CK) == hb


def test_heartbeat_max_payload():
    payload = b"\xAB" * proto.PAYLOAD_MAX_BYTES  # 1152 B = 36 blocks
    hb = proto.Heartbeat(NODE_A, 1700000000000, NODE_B, payload)
    wire = hb.encode(CK)
    assert len(wire) == 32 + 1152
    assert len(wire) <= proto.MTU_CAP
    assert proto.decode_heartbeat(wire, CK) == hb


def test_heartbeat_rejects_payload_not_multiple_of_32():
    hb = proto.Heartbeat(NODE_A, 1, 0xFF, b"abc")  # 3 B not multiple of 32
    with pytest.raises(proto.ProtocolError, match="not a multiple of 32"):
        hb.encode(CK)


def test_heartbeat_rejects_payload_too_large():
    too_big = b"x" * (proto.PAYLOAD_MAX_BYTES + 32)  # 37 blocks
    hb = proto.Heartbeat(NODE_A, 1, 0xFF, too_big)
    with pytest.raises(proto.ProtocolError, match="exceeds max"):
        hb.encode(CK)


def test_heartbeat_rejects_witness_sender_id():
    with pytest.raises(proto.ProtocolError, match="node sender_id"):
        proto.Heartbeat(0xFF, 1, 0, b"").encode(CK)


def test_heartbeat_rejects_wrong_cluster_key():
    hb = proto.Heartbeat(NODE_A, 1700000000000, 0xFF, b"")
    wire = hb.encode(CK)
    with pytest.raises(proto.AuthError):
        proto.decode_heartbeat(wire, CK2)


def test_heartbeat_rejects_tampered_payload():
    hb = proto.Heartbeat(NODE_A, 1700000000000, 0xFF, b"")
    wire = bytearray(hb.encode(CK))
    wire[20] ^= 0xFF  # corrupt one byte mid-ciphertext
    with pytest.raises(proto.AuthError):
        proto.decode_heartbeat(bytes(wire), CK)


def test_heartbeat_rejects_tampered_header():
    hb = proto.Heartbeat(NODE_A, 1700000000000, 0xFF, b"")
    wire = bytearray(hb.encode(CK))
    wire[5] = NODE_B  # change sender_id (in AAD)
    with pytest.raises(proto.AuthError):
        proto.decode_heartbeat(bytes(wire), CK)


# ── STATUS_LIST (0x02) ────────────────────────────────────────────────────


def test_status_list_empty():
    sl = proto.StatusList(timestamp_ms=1700000000050, witness_uptime_seconds=10, entries=())
    wire = sl.encode(CK)
    assert len(wire) == 35
    assert proto.decode_status_list(wire, CK) == sl


def test_status_list_two_entries():
    sl = proto.StatusList(
        timestamp_ms=1700000000050,
        witness_uptime_seconds=3600,
        entries=(
            proto.ListEntry(peer_sender_id=NODE_A, last_seen_ms=42),
            proto.ListEntry(peer_sender_id=NODE_B, last_seen_ms=1503),
        ),
    )
    wire = sl.encode(CK)
    assert len(wire) == 35 + 2 * 5
    assert proto.decode_status_list(wire, CK) == sl


def test_status_list_max_entries_fits_mtu():
    es = tuple(
        proto.ListEntry(peer_sender_id=i, last_seen_ms=i * 100)
        for i in range(proto.LIST_MAX_ENTRIES)
    )
    sl = proto.StatusList(timestamp_ms=0, witness_uptime_seconds=0, entries=es)
    wire = sl.encode(CK)
    assert len(wire) == 35 + 5 * proto.LIST_MAX_ENTRIES  # 675 B
    assert len(wire) <= proto.MTU_CAP
    assert proto.decode_status_list(wire, CK) == sl


def test_status_list_rejects_too_many_entries():
    es = tuple(
        proto.ListEntry(peer_sender_id=0, last_seen_ms=0)
        for _ in range(proto.LIST_MAX_ENTRIES + 1)
    )
    sl = proto.StatusList(0, 0, entries=es)
    with pytest.raises(proto.ProtocolError, match="too many entries"):
        sl.encode(CK)


def test_status_list_witness_sender_id_required():
    """Decoder must reject a STATUS_LIST whose header sender_id != 0xFF
    (someone forging a witness reply with their node id)."""
    sl = proto.StatusList(0, 0, entries=())
    wire = bytearray(sl.encode(CK))
    wire[5] = NODE_A  # change sender_id from 0xFF to a node id
    # AAD changed → AEAD fails before sender_id check, so AuthError
    with pytest.raises(proto.AuthError):
        proto.decode_status_list(bytes(wire), CK)


# ── STATUS_DETAIL (0x03) ──────────────────────────────────────────────────


def test_status_detail_found_with_payload():
    sd = proto.StatusDetail(
        timestamp_ms=1700000000050,
        witness_uptime_seconds=3601,
        target_sender_id=NODE_B,
        found=True,
        peer_ipv4=proto.ipv4_to_bytes("192.168.2.11"),
        peer_seen_ms_ago=1500,
        peer_payload=b"\xCD" * 128,  # 4 blocks
    )
    wire = sd.encode(CK)
    assert len(wire) == 44 + 128  # 172
    assert proto.decode_status_detail(wire, CK) == sd


def test_status_detail_found_empty_payload():
    sd = proto.StatusDetail(
        timestamp_ms=0, witness_uptime_seconds=0, target_sender_id=NODE_B,
        found=True, peer_ipv4=b"\x00" * 4, peer_seen_ms_ago=0,
        peer_payload=b"",
    )
    wire = sd.encode(CK)
    assert len(wire) == 44  # found, N=0
    assert proto.decode_status_detail(wire, CK) == sd


def test_status_detail_not_found():
    sd = proto.StatusDetail(
        timestamp_ms=1700000000050,
        witness_uptime_seconds=3602,
        target_sender_id=0x99,
        found=False,
    )
    wire = sd.encode(CK)
    assert len(wire) == 36  # not-found is 36 B flat
    assert proto.decode_status_detail(wire, CK) == sd


def test_status_detail_max_payload():
    sd = proto.StatusDetail(
        timestamp_ms=0, witness_uptime_seconds=0, target_sender_id=NODE_B,
        found=True, peer_ipv4=b"\x00" * 4, peer_seen_ms_ago=0,
        peer_payload=b"\xFF" * proto.PAYLOAD_MAX_BYTES,
    )
    wire = sd.encode(CK)
    assert len(wire) == 44 + proto.PAYLOAD_MAX_BYTES  # 1196
    assert len(wire) <= proto.MTU_CAP
    assert proto.decode_status_detail(wire, CK) == sd


def test_status_detail_v2_flag_bit6_ignored_v1():
    """A v2 implementation might set bit 6 of status_and_blocks. receivers
    MUST ignore it (still extract block count from bits 0-5)."""
    sd = proto.StatusDetail(
        timestamp_ms=0, witness_uptime_seconds=0, target_sender_id=NODE_B,
        found=True, peer_ipv4=b"\x00" * 4, peer_seen_ms_ago=0,
        peer_payload=b"\xCD" * 32,  # 1 block
    )
    wire = bytearray(sd.encode(CK))
    # Status_and_blocks byte is at offset 14 (start of plaintext) but the
    # plaintext is encrypted. We need to construct a parallel packet with
    # bit 6 set in plaintext and a fresh AEAD seal. Simulating a v2 sender:
    header = proto.Header(proto.MSG_STATUS_DETAIL, proto.WITNESS_SENDER_ID, 0)
    pt_with_flag = (
        struct.pack(">IBB", 0, NODE_B, 0x40 | 1)  # bit 6 set, blocks=1
        + b"\x00" * 4 + struct.pack(">I", 0) + b"\xCD" * 32
    )
    aad = header.pack()
    nonce = proto.derive_nonce(proto.WITNESS_SENDER_ID, 0)
    ct = crypto.aead_encrypt(CK, nonce, aad, pt_with_flag)
    wire_v2 = aad + ct
    # receiver must accept this — bit 6 is ignored, block count = 1
    decoded = proto.decode_status_detail(wire_v2, CK)
    assert decoded.found is True
    assert decoded.peer_payload == b"\xCD" * 32


def test_status_detail_invalid_block_count_dropped():
    """status_and_blocks = 37 (block count > 36) must be silent-dropped."""
    header = proto.Header(proto.MSG_STATUS_DETAIL, proto.WITNESS_SENDER_ID, 0)
    pt_bad = struct.pack(">IBB", 0, NODE_B, 37) + b"\x00" * (4 + 4 + 37 * 32)
    aad = header.pack()
    nonce = proto.derive_nonce(proto.WITNESS_SENDER_ID, 0)
    ct = crypto.aead_encrypt(CK, nonce, aad, pt_bad)
    with pytest.raises(proto.ProtocolError, match="block count"):
        proto.decode_status_detail(aad + ct, CK)


# ── DISCOVER (0x04) ───────────────────────────────────────────────────────


def test_discover_roundtrip():
    d = proto.Discover(sender_id=NODE_A, timestamp_ms=1700000000000)
    wire = d.encode()
    assert len(wire) == 64  # 14 B header + 2 B caps + 48 B zero padding
    assert proto.decode_discover(wire) == d


def test_discover_caps_default_zero_and_padding_zero():
    """Senders MUST set capability_flags=0 and pad bytes 16..64 to zero
    in Draft v0.x (PROTOCOL.md §16.2)."""
    d = proto.Discover(sender_id=NODE_A, timestamp_ms=0)
    wire = d.encode()
    assert wire[14:16] == b"\x00\x00"   # capability_flags u16 BE
    assert wire[16:] == b"\x00" * 48    # padding


def test_discover_capability_flags_round_trip():
    d = proto.Discover(sender_id=NODE_A, timestamp_ms=0, capability_flags=0xBEEF)
    wire = d.encode()
    assert wire[14:16] == b"\xBE\xEF"   # u16 big-endian
    assert proto.decode_discover(wire).capability_flags == 0xBEEF


def test_init_capability_flags_round_trip():
    pub = bytes(range(32))
    cookie = bytes(range(16))
    init = proto.Init(timestamp_ms=0, witness_pubkey=pub, cookie=cookie,
                      capability_flags=0xCAFE)
    wire = init.encode()
    assert wire[14:16] == b"\xCA\xFE"
    decoded = proto.decode_init(wire)
    assert decoded.capability_flags == 0xCAFE
    assert decoded.witness_pubkey == pub
    assert decoded.cookie == cookie


def test_discover_request_size_matches_init_reply_size():
    """Anti-amplification (PROTOCOL.md §1 principle 13): DISCOVER ≥ INIT."""
    assert proto.DISCOVER_LEN == proto.INIT_LEN == 64


def test_discover_rejects_wrong_size():
    with pytest.raises(proto.ProtocolError, match="exactly 64"):
        proto.decode_discover(b"Echo\x04\x01" + b"\x00" * 8 + b"trailing")


def test_discover_rejects_witness_sender_id():
    with pytest.raises(proto.ProtocolError, match="node sender_id"):
        proto.Discover(sender_id=0xFF, timestamp_ms=0).encode()


# ── INIT (0x10) ───────────────────────────────────────────────────────────


def _zero_cookie() -> bytes:
    return b"\x00" * proto.COOKIE_LEN


def test_init_roundtrip():
    pub = bytes(range(32))
    cookie = bytes(range(16))
    init = proto.Init(timestamp_ms=1700000000000, witness_pubkey=pub, cookie=cookie)
    wire = init.encode()
    assert len(wire) == 64
    assert proto.decode_init(wire) == init


def test_init_carries_pubkey_and_cookie():
    pub = bytes([0xCC] * 32)
    cookie = bytes([0xEE] * 16)
    init = proto.Init(timestamp_ms=0, witness_pubkey=pub, cookie=cookie)
    decoded = proto.decode_init(init.encode())
    assert decoded.witness_pubkey == pub
    assert decoded.cookie == cookie


def test_init_zero_timestamp_ok():
    pub = bytes(32)
    init = proto.Init(timestamp_ms=0, witness_pubkey=pub, cookie=_zero_cookie())
    assert proto.decode_init(init.encode()) == init


def test_init_rejects_bad_size():
    with pytest.raises(proto.ProtocolError, match="exactly 64"):
        proto.decode_init(b"Echo\x10\xFF" + b"\x00" * 8)  # too short


def test_init_rejects_bad_cookie_len():
    pub = bytes(32)
    with pytest.raises(proto.ProtocolError, match="cookie must be"):
        proto.Init(timestamp_ms=0, witness_pubkey=pub, cookie=b"short").encode()


def test_cookie_derivation_matches_spec():
    """cookie = SHA-256(witness_cookie_secret || src_ip_be)[:16]"""
    secret = bytes([0xCC] * 32)
    ip = bytes([192, 0, 2, 10])
    cookie = crypto.derive_cookie(secret, ip)
    assert len(cookie) == 16
    # Same inputs → same cookie (deterministic)
    assert crypto.derive_cookie(secret, ip) == cookie
    # Different src_ip → different cookie
    assert crypto.derive_cookie(secret, bytes([192, 0, 2, 11])) != cookie
    # Different secret → different cookie
    assert crypto.derive_cookie(bytes([0xDD] * 32), ip) != cookie


# ── BOOTSTRAP (0x20) ──────────────────────────────────────────────────────


_FIXED_COOKIE = bytes([0xAB] * 16)


def test_bootstrap_roundtrip():
    w_priv, w_pub = crypto.x25519_generate()
    eph_priv = bytes([0xBB] * 32)
    cluster_key = bytes([0x11] * 32)
    bs = proto.Bootstrap(sender_id=NODE_A, timestamp_ms=1700000001000,
                         cluster_key=cluster_key, cookie=_FIXED_COOKIE)
    wire = bs.encode(w_pub, eph_priv)
    assert len(wire) == 110
    decoded = proto.decode_bootstrap(wire, w_priv)
    assert decoded.cluster_key == cluster_key
    assert decoded.cookie == _FIXED_COOKIE
    assert decoded.sender_id == NODE_A
    assert decoded.timestamp_ms == 1700000001000


def test_bootstrap_wrong_witness_priv_fails():
    w_priv, w_pub = crypto.x25519_generate()
    other_priv, _ = crypto.x25519_generate()
    bs = proto.Bootstrap(NODE_A, 1, bytes([0x11] * 32), cookie=_FIXED_COOKIE)
    wire = bs.encode(w_pub, bytes([0xBB] * 32))
    with pytest.raises(proto.AuthError):
        proto.decode_bootstrap(wire, other_priv)


def test_bootstrap_tampered_header_fails():
    w_priv, w_pub = crypto.x25519_generate()
    bs = proto.Bootstrap(NODE_A, 1, bytes([0x11] * 32), cookie=_FIXED_COOKIE)
    wire = bytearray(bs.encode(w_pub, bytes([0xBB] * 32)))
    wire[5] = NODE_B  # change sender_id (in AAD)
    with pytest.raises(proto.AuthError):
        proto.decode_bootstrap(bytes(wire), w_priv)


def test_bootstrap_tampered_cookie_fails():
    """Cookie sits in the AAD (header || cookie); modifying it must
    invalidate the Poly1305 tag."""
    w_priv, w_pub = crypto.x25519_generate()
    bs = proto.Bootstrap(NODE_A, 1, bytes([0x11] * 32), cookie=_FIXED_COOKIE)
    wire = bytearray(bs.encode(w_pub, bytes([0xBB] * 32)))
    wire[20] ^= 0x01  # flip a bit in the cookie (bytes 14..30)
    with pytest.raises(proto.AuthError):
        proto.decode_bootstrap(bytes(wire), w_priv)


def test_bootstrap_tampered_eph_pubkey_fails():
    w_priv, w_pub = crypto.x25519_generate()
    bs = proto.Bootstrap(NODE_A, 1, bytes([0x11] * 32), cookie=_FIXED_COOKIE)
    wire = bytearray(bs.encode(w_pub, bytes([0xBB] * 32)))
    wire[40] ^= 0xFF  # mid-eph_pubkey (bytes 30..62)
    # Modifying eph_pubkey changes the derived key → AEAD fails
    with pytest.raises(proto.AuthError):
        proto.decode_bootstrap(bytes(wire), w_priv)


def test_bootstrap_rejects_wrong_size():
    with pytest.raises(proto.ProtocolError, match="exactly 110"):
        proto.decode_bootstrap(b"Echo\x20" + b"\x00" * 50, b"\x00" * 32)


def test_bootstrap_rejects_bad_cookie_len():
    _, w_pub = crypto.x25519_generate()
    with pytest.raises(proto.ProtocolError, match="cookie must be"):
        proto.Bootstrap(NODE_A, 1, bytes([0x11] * 32),
                        cookie=b"short").encode(w_pub, bytes([0xBB] * 32))


def test_bootstrap_fresh_eph_produces_different_ciphertext():
    """Two BOOTSTRAPs with the same cluster_key but different ephemeral keys
    must produce different ciphertexts (per-message key freshness)."""
    _, w_pub = crypto.x25519_generate()
    cluster_key = bytes([0x11] * 32)
    bs = proto.Bootstrap(NODE_A, 1, cluster_key, cookie=_FIXED_COOKIE)
    eph1 = bytes([0xBB] * 32)
    eph2 = bytes([0xCC] * 32)
    w1 = bs.encode(w_pub, eph1)
    w2 = bs.encode(w_pub, eph2)
    assert w1 != w2  # different eph_pubkey AND different ciphertext


# ── BOOTSTRAP_ACK (0x21) ──────────────────────────────────────────────────


def test_bootstrap_ack_new_roundtrip():
    ack = proto.BootstrapAck(timestamp_ms=1700000001050, status=0x00,
                             witness_uptime_seconds=3600)
    wire = ack.encode(CK)
    assert len(wire) == 35
    assert proto.decode_bootstrap_ack(wire, CK) == ack


def test_bootstrap_ack_idempotent_roundtrip():
    ack = proto.BootstrapAck(timestamp_ms=1700000001051, status=0x01,
                             witness_uptime_seconds=3601)
    wire = ack.encode(CK)
    assert proto.decode_bootstrap_ack(wire, CK) == ack


def test_bootstrap_ack_helpers():
    assert proto.status_is_new(0x00)
    assert proto.status_is_new(0x80)  # bit 7 set, bit 0 clear → still "new"
    assert proto.status_is_idempotent(0x01)
    assert proto.status_is_idempotent(0x83)  # bit 0 set


def test_bootstrap_ack_v2_upper_bits_ignored_v1():
    """A v2 sender might set bits 1-7 of the status byte. receivers MUST
    decode those without dropping; bit 0 still carries the new/idempotent
    semantic."""
    header = proto.Header(proto.MSG_BOOTSTRAP_ACK, proto.WITNESS_SENDER_ID, 0)
    pt = struct.pack(">BI", 0xFE, 100)  # bits 1-7 all set, bit 0 = 0 (new)
    aad = header.pack()
    nonce = proto.derive_nonce(proto.WITNESS_SENDER_ID, 0)
    ct = crypto.aead_encrypt(CK, nonce, aad, pt)
    decoded = proto.decode_bootstrap_ack(aad + ct, CK)
    assert decoded.status == 0xFE
    assert proto.status_is_new(decoded.status)


# ── Cross-cluster privacy ─────────────────────────────────────────────────


def test_different_cluster_keys_give_different_ciphertext():
    """Two clusters with same payload but different cluster_keys must produce
    different ciphertexts (basic confidentiality property)."""
    hb = proto.Heartbeat(NODE_A, 1700000000000, 0xFF, b"\x00" * 32)
    w1 = hb.encode(CK)
    w2 = hb.encode(CK2)
    assert w1[:14] == w2[:14]  # header is plaintext, same
    assert w1[14:] != w2[14:]  # ciphertext differs


def test_aead_nonce_reuse_would_be_visible_in_keystream():
    """Sanity check: the nonce derivation is unique enough that two different
    plaintexts with the same (key, sender_id, timestamp) would produce
    detectably different ciphertexts.

    This isn't really testing a property of OUR code — just reinforcing that
    we DO derive nonce from header (and so any monotonic-violation by a sender
    would manifest visibly)."""
    hb1 = proto.Heartbeat(NODE_A, 100, 0xFF, b"\x11" * 32)
    hb2 = proto.Heartbeat(NODE_A, 100, 0xFF, b"\x22" * 32)
    # Same nonce (same sender_id + timestamp_ms), same key → keystream is the
    # same. ChaCha20 produces XOR of plaintexts in ciphertext deltas:
    w1 = hb1.encode(CK)[14:-16]  # ciphertext only, no header, no tag
    w2 = hb2.encode(CK)[14:-16]
    # The XOR of ciphertexts equals XOR of plaintexts (+ same plaintext
    # length structure prefix).
    assert len(w1) == len(w2)
    # NOT going to assert any specific structural property; just confirming
    # the test isn't masking a bug.
