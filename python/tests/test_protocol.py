"""Round-trip and structural tests for the Bedrock Echo protocol.

Run from the repo root:
    PYTHONPATH=python python3 -m pytest python/tests/ -v
"""
from __future__ import annotations

import os
import struct
import sys
import pytest

# allow `python/tests/` to import the `echo` package when invoked directly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from echo import proto, crypto  # noqa: E402


CK = b"K" * 32   # fixed test cluster key
SID = b"A" * 8
WID = b"W" * 8


def test_heartbeat_roundtrip_list_query():
    hb = proto.Heartbeat(
        sender_id=SID, sequence=1, timestamp_ms=1700000000000,
        query_target_id=b"\x00" * 8, own_payload=b"hello",
    )
    wire = hb.encode(CK)
    assert 32 + 8 + 5 + 32 == len(wire)
    out = proto.decode_heartbeat(wire, CK)
    assert out == hb


def test_heartbeat_roundtrip_detail_query():
    hb = proto.Heartbeat(
        sender_id=SID, sequence=2, timestamp_ms=1700000000001,
        query_target_id=b"B" * 8,
        own_payload=b"drbd:primary,uuid=0xdeadbeef",
    )
    wire = hb.encode(CK)
    assert proto.decode_heartbeat(wire, CK) == hb


def test_heartbeat_rejects_bad_hmac():
    hb = proto.Heartbeat(SID, 1, 0, b"\x00" * 8, b"")
    wire = hb.encode(CK)
    tampered = wire[:-1] + bytes([wire[-1] ^ 0xFF])
    with pytest.raises(proto.AuthError):
        proto.decode_heartbeat(tampered, CK)


def test_heartbeat_rejects_wrong_key():
    hb = proto.Heartbeat(SID, 1, 0, b"\x00" * 8, b"")
    wire = hb.encode(CK)
    with pytest.raises(proto.AuthError):
        proto.decode_heartbeat(wire, b"X" * 32)


def test_heartbeat_rejects_bad_magic():
    hb = proto.Heartbeat(SID, 1, 0, b"\x00" * 8, b"")
    wire = bytearray(hb.encode(CK))
    wire[0] = ord("X")
    # re-HMAC so only the magic is wrong
    wire[-32:] = crypto.hmac_sha256(CK, bytes(wire[:-32]))
    with pytest.raises(proto.ProtocolError):
        proto.decode_heartbeat(bytes(wire), CK)


def test_status_list_roundtrip_empty():
    sl = proto.StatusList(
        sender_id=WID, sequence=1, timestamp_ms=0,
        witness_uptime_ms=42000, entries=(),
    )
    assert proto.decode_status_list(sl.encode(CK), CK) == sl


def test_status_list_roundtrip_two_entries():
    es = (
        proto.ListEntry(peer_sender_id=b"A" * 8,
                        peer_ipv4=proto.ipv4_to_bytes("192.168.2.10"),
                        last_seen_seconds=1),
        proto.ListEntry(peer_sender_id=b"B" * 8,
                        peer_ipv4=proto.ipv4_to_bytes("192.168.2.11"),
                        last_seen_seconds=3),
    )
    sl = proto.StatusList(WID, 7, 0, 60000, entries=es)
    out = proto.decode_status_list(sl.encode(CK), CK)
    assert out == sl


def test_status_list_fits_64_entries_in_mtu():
    es = tuple(
        proto.ListEntry(peer_sender_id=bytes([i] * 8),
                        peer_ipv4=bytes([192, 168, 2, i % 256]),
                        last_seen_seconds=i)
        for i in range(64)
    )
    sl = proto.StatusList(WID, 1, 0, 1, entries=es)
    wire = sl.encode(CK)
    assert len(wire) <= proto.MTU_CAP
    assert proto.decode_status_list(wire, CK) == sl


def test_status_detail_roundtrip_found():
    sd = proto.StatusDetail(
        sender_id=WID, sequence=1, timestamp_ms=0,
        witness_uptime_ms=123456,
        target_sender_id=b"B" * 8, status=0x00,
        peer_ipv4=proto.ipv4_to_bytes("192.168.2.11"),
        last_seen_seconds=5,
        peer_payload=b"role=primary,conn=UpToDate",
    )
    assert proto.decode_status_detail(sd.encode(CK), CK) == sd


def test_status_detail_roundtrip_not_found():
    sd = proto.StatusDetail(
        sender_id=WID, sequence=2, timestamp_ms=0,
        witness_uptime_ms=123456,
        target_sender_id=b"X" * 8, status=0x01,
    )
    assert proto.decode_status_detail(sd.encode(CK), CK) == sd


def test_unknown_source_roundtrip():
    us = proto.UnknownSource(sender_id=WID, sequence=1, timestamp_ms=0)
    wire = us.encode()
    assert len(wire) == 32
    assert proto.decode_unknown_source(wire) == us


def test_bootstrap_and_decrypt():
    w_priv, w_pub = crypto.x25519_generate()
    # Deterministic eph for reproducibility:
    eph_priv = bytes(range(32))
    cluster_key = b"K" * 32
    bs = proto.Bootstrap(
        sender_id=SID, sequence=100, timestamp_ms=1_700_000_000_000,
        cluster_key=cluster_key, init_payload=b"init!",
    )
    wire = bs.encode(w_pub, eph_priv)
    # server-side decrypt
    decoded = proto.decode_bootstrap(wire, w_priv)
    assert decoded.cluster_key == cluster_key
    assert decoded.init_payload == b"init!"
    assert decoded.sender_id == SID


def test_bootstrap_tampered_header_fails():
    w_priv, w_pub = crypto.x25519_generate()
    eph_priv = bytes(range(32))
    bs = proto.Bootstrap(SID, 1, 0, b"K" * 32)
    wire = bytearray(bs.encode(w_pub, eph_priv))
    wire[15] ^= 0xFF  # corrupt a byte in sequence field (part of AAD)
    with pytest.raises(proto.AuthError):
        proto.decode_bootstrap(bytes(wire), w_priv)


def test_bootstrap_ack_roundtrip():
    ack = proto.BootstrapAck(
        sender_id=WID, sequence=10, timestamp_ms=0,
        status=0x00, witness_uptime_ms=999,
    )
    wire = ack.encode(CK)
    assert proto.decode_bootstrap_ack(wire, CK) == ack


def test_sender_id_zero_rejected():
    with pytest.raises(proto.ProtocolError):
        proto.Heartbeat(
            sender_id=b"\x00" * 8, sequence=1, timestamp_ms=0,
            query_target_id=b"\x00" * 8, own_payload=b"",
        ).encode(CK)


def test_nonzero_flags_rejected_on_decode():
    hb = proto.Heartbeat(SID, 1, 0, b"\x00" * 8, b"")
    wire = bytearray(hb.encode(CK))
    wire[5] = 0x01  # flags
    wire[-32:] = crypto.hmac_sha256(CK, bytes(wire[:-32]))
    with pytest.raises(proto.ProtocolError):
        proto.decode_heartbeat(bytes(wire), CK)
