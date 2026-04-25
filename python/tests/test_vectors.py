"""Cross-language test vector validation.

These vectors are the canonical contract that ALL implementations
(Python, Rust, C/ESP32, future ports) must satisfy. For each vector pair:

  - Encode the inputs in .in.json and verify the output is byte-exact
    with .out.bin.
  - Decode .out.bin and verify the round-trip matches the inputs.

Any conformant implementation passes all 12 vectors with byte-perfect
output.

Run from the repo root:
    PYTHONPATH=python python3 -m pytest python/tests/test_vectors.py -v
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from echo import proto, crypto  # noqa: E402

VECTOR_DIR = Path(__file__).resolve().parents[2] / "testvectors"


def vector(name: str) -> tuple[dict, bytes]:
    """Load the (.in.json, .out.bin) pair for a named vector."""
    in_path = VECTOR_DIR / f"{name}.in.json"
    out_path = VECTOR_DIR / f"{name}.out.bin"
    if not in_path.exists() or not out_path.exists():
        pytest.skip(f"vector files missing for {name}")
    inputs = json.loads(in_path.read_text())
    out_bytes = out_path.read_bytes()
    return inputs, out_bytes


# ── 01 HEARTBEAT list query ───────────────────────────────────────────────


def test_vector_01_heartbeat_list_query():
    inputs, expected = vector("01_heartbeat_list_query")
    ck = bytes.fromhex(inputs["cluster_key"])
    own_payload = bytes.fromhex(inputs["own_payload"])
    hb = proto.Heartbeat(
        sender_id=inputs["sender_id"],
        timestamp_ms=inputs["timestamp_ms"],
        query_target_id=inputs["query_target_id"],
        own_payload=own_payload,
    )
    wire = hb.encode(ck)
    assert wire == expected
    decoded = proto.decode_heartbeat(wire, ck)
    assert decoded.sender_id == inputs["sender_id"]
    assert decoded.timestamp_ms == inputs["timestamp_ms"]
    assert decoded.query_target_id == inputs["query_target_id"]
    assert decoded.own_payload == own_payload


# ── 02 HEARTBEAT detail query ─────────────────────────────────────────────


def test_vector_02_heartbeat_detail_query():
    inputs, expected = vector("02_heartbeat_detail_query")
    ck = bytes.fromhex(inputs["cluster_key"])
    own_payload = bytes.fromhex(inputs["own_payload"])
    hb = proto.Heartbeat(
        sender_id=inputs["sender_id"],
        timestamp_ms=inputs["timestamp_ms"],
        query_target_id=inputs["query_target_id"],
        own_payload=own_payload,
    )
    assert hb.encode(ck) == expected
    decoded = proto.decode_heartbeat(expected, ck)
    assert decoded == hb


# ── 03 HEARTBEAT self query ───────────────────────────────────────────────


def test_vector_03_heartbeat_self_query():
    inputs, expected = vector("03_heartbeat_self_query")
    ck = bytes.fromhex(inputs["cluster_key"])
    own_payload = bytes.fromhex(inputs["own_payload"])
    hb = proto.Heartbeat(
        sender_id=inputs["sender_id"],
        timestamp_ms=inputs["timestamp_ms"],
        query_target_id=inputs["query_target_id"],
        own_payload=own_payload,
    )
    assert hb.encode(ck) == expected
    decoded = proto.decode_heartbeat(expected, ck)
    assert decoded == hb
    # Self-query: target equals sender's own id
    assert decoded.query_target_id == decoded.sender_id


# ── 04 STATUS_LIST two nodes ──────────────────────────────────────────────


def test_vector_04_status_list_two_nodes():
    inputs, expected = vector("04_status_list_two_nodes")
    ck = bytes.fromhex(inputs["cluster_key"])
    entries = tuple(
        proto.ListEntry(peer_sender_id=e["peer_sender_id"],
                        last_seen_ms=e["last_seen_ms"])
        for e in inputs["entries"]
    )
    sl = proto.StatusList(
        timestamp_ms=inputs["timestamp_ms"],
        witness_uptime_seconds=inputs["witness_uptime_seconds"],
        entries=entries,
    )
    assert sl.encode(ck) == expected
    decoded = proto.decode_status_list(expected, ck)
    assert decoded == sl


# ── 05 STATUS_LIST empty ──────────────────────────────────────────────────


def test_vector_05_status_list_empty():
    inputs, expected = vector("05_status_list_empty")
    ck = bytes.fromhex(inputs["cluster_key"])
    sl = proto.StatusList(
        timestamp_ms=inputs["timestamp_ms"],
        witness_uptime_seconds=inputs["witness_uptime_seconds"],
        entries=(),
    )
    assert sl.encode(ck) == expected
    assert proto.decode_status_list(expected, ck) == sl


# ── 06 STATUS_DETAIL found ────────────────────────────────────────────────


def test_vector_06_status_detail_found():
    inputs, expected = vector("06_status_detail_found")
    ck = bytes.fromhex(inputs["cluster_key"])
    sd = proto.StatusDetail(
        timestamp_ms=inputs["timestamp_ms"],
        witness_uptime_seconds=inputs["witness_uptime_seconds"],
        target_sender_id=inputs["target_sender_id"],
        found=inputs["found"],
        peer_ipv4=proto.ipv4_to_bytes(inputs["peer_ipv4"]),
        peer_seen_ms_ago=inputs["peer_seen_ms_ago"],
        peer_payload=bytes.fromhex(inputs["peer_payload"]),
    )
    assert sd.encode(ck) == expected
    assert proto.decode_status_detail(expected, ck) == sd


# ── 07 STATUS_DETAIL not found ────────────────────────────────────────────


def test_vector_07_status_detail_not_found():
    inputs, expected = vector("07_status_detail_not_found")
    ck = bytes.fromhex(inputs["cluster_key"])
    sd = proto.StatusDetail(
        timestamp_ms=inputs["timestamp_ms"],
        witness_uptime_seconds=inputs["witness_uptime_seconds"],
        target_sender_id=inputs["target_sender_id"],
        found=inputs["found"],
    )
    assert sd.encode(ck) == expected
    assert proto.decode_status_detail(expected, ck) == sd


# ── 08 DISCOVER ───────────────────────────────────────────────────────────


def test_vector_08_discover():
    inputs, expected = vector("08_discover")
    d = proto.Discover(sender_id=inputs["sender_id"],
                       timestamp_ms=inputs["timestamp_ms"])
    assert d.encode() == expected
    assert proto.decode_discover(expected) == d


# ── 09 UNKNOWN_SOURCE ─────────────────────────────────────────────────────


def test_vector_09_unknown_source():
    inputs, expected = vector("09_unknown_source")
    pub = bytes.fromhex(inputs["witness_pubkey"])
    us = proto.UnknownSource(timestamp_ms=inputs["timestamp_ms"],
                             witness_pubkey=pub)
    assert us.encode() == expected
    assert proto.decode_unknown_source(expected) == us


# ── 10 BOOTSTRAP ──────────────────────────────────────────────────────────


def test_vector_10_bootstrap():
    inputs, expected = vector("10_bootstrap")
    cluster_key = bytes.fromhex(inputs["cluster_key"])
    witness_pubkey = bytes.fromhex(inputs["witness_pubkey"])
    eph_priv = bytes.fromhex(inputs["eph_priv"])
    bs = proto.Bootstrap(
        sender_id=inputs["sender_id"],
        timestamp_ms=inputs["timestamp_ms"],
        cluster_key=cluster_key,
    )
    wire = bs.encode(witness_pubkey, eph_priv)
    assert wire == expected

    # Decode requires the witness's PRIVATE key. We re-derive it from the
    # known seed used in the generator script.
    witness_priv = bytes([0xAA] * 32)
    decoded = proto.decode_bootstrap(expected, witness_priv)
    assert decoded.sender_id == inputs["sender_id"]
    assert decoded.timestamp_ms == inputs["timestamp_ms"]
    assert decoded.cluster_key == cluster_key


# ── 11 BOOTSTRAP_ACK new ──────────────────────────────────────────────────


def test_vector_11_bootstrap_ack_new():
    inputs, expected = vector("11_bootstrap_ack_new")
    ck = bytes.fromhex(inputs["cluster_key"])
    ack = proto.BootstrapAck(
        timestamp_ms=inputs["timestamp_ms"],
        status=inputs["status"],
        witness_uptime_seconds=inputs["witness_uptime_seconds"],
    )
    assert ack.encode(ck) == expected
    decoded = proto.decode_bootstrap_ack(expected, ck)
    assert decoded == ack
    assert proto.status_is_new(decoded.status)


# ── 12 BOOTSTRAP_ACK idempotent ───────────────────────────────────────────


def test_vector_12_bootstrap_ack_rebootstrap():
    inputs, expected = vector("12_bootstrap_ack_rebootstrap")
    ck = bytes.fromhex(inputs["cluster_key"])
    ack = proto.BootstrapAck(
        timestamp_ms=inputs["timestamp_ms"],
        status=inputs["status"],
        witness_uptime_seconds=inputs["witness_uptime_seconds"],
    )
    assert ack.encode(ck) == expected
    decoded = proto.decode_bootstrap_ack(expected, ck)
    assert proto.status_is_idempotent(decoded.status)


# ── Manifest sanity ───────────────────────────────────────────────────────


def test_all_vectors_present():
    """All 12 vectors must be on disk."""
    expected_names = [
        "01_heartbeat_list_query",
        "02_heartbeat_detail_query",
        "03_heartbeat_self_query",
        "04_status_list_two_nodes",
        "05_status_list_empty",
        "06_status_detail_found",
        "07_status_detail_not_found",
        "08_discover",
        "09_unknown_source",
        "10_bootstrap",
        "11_bootstrap_ack_new",
        "12_bootstrap_ack_rebootstrap",
    ]
    for name in expected_names:
        assert (VECTOR_DIR / f"{name}.in.json").exists(), name
        assert (VECTOR_DIR / f"{name}.out.bin").exists(), name
