"""Cross-language live interop tests (v1).

Talks to a running Bedrock Echo witness binary (Rust or C/ESP32) from
the Python NodeClient. Skipped unless BEDROCK_ECHO_WITNESS_ADDR is set.

Usage:
    # Get the witness pubkey (e.g., for the live ESP32):
    BEDROCK_ECHO_WITNESS_ADDR=192.168.2.181:12321 \\
    BEDROCK_ECHO_WITNESS_PUB=800b1f47ff88dcf2792b68756a7d25323e6a1db2e38017c862363e1f22d16779 \\
    PYTHONPATH=python python3 -m pytest python/tests/test_interop_live.py -v
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from echo import proto, crypto  # noqa: E402
from echo.node import NodeClient  # noqa: E402


# Witness rate-limits incoming traffic at 10 pps + burst 20 per source IP,
# and additionally caps UNKNOWN_SOURCE replies at 1/sec/IP. Tests in this
# module run many packets in tight succession from a single source IP, so
# we yield briefly between tests to keep the witness's rate-limit budget
# refreshed.
UNKNOWN_RATE_DELAY = 1.2


@pytest.fixture(autouse=True)
def _rate_limit_breather():
    """Yield briefly between tests so the witness's per-IP rate limit
    refreshes and we don't starve subsequent tests of UNKNOWN_SOURCE
    replies or burst tokens."""
    yield
    time.sleep(1.5)


ADDR = os.environ.get("BEDROCK_ECHO_WITNESS_ADDR")
PUB_HEX = os.environ.get("BEDROCK_ECHO_WITNESS_PUB")


@pytest.fixture(scope="module")
def addr():
    if not ADDR or not PUB_HEX:
        pytest.skip("set BEDROCK_ECHO_WITNESS_ADDR and BEDROCK_ECHO_WITNESS_PUB")
    host, port = ADDR.split(":")
    return (host, int(port))


@pytest.fixture(scope="module")
def pub():
    return bytes.fromhex(PUB_HEX)


@pytest.fixture(scope="module")
def cluster_key():
    # Random per test run. The witness collision-resolution semantics mean
    # that even if a previous run left a node entry under a different
    # cluster_key, our new BOOTSTRAP creates a new entry alongside.
    return crypto.random_bytes(32)


def test_discover_returns_witness_pubkey(addr, pub):
    """DISCOVER → UNKNOWN_SOURCE with witness's pubkey."""
    n = NodeClient(sender_id=0x01, cluster_key=b"\x00" * 32,
                   witness_addr=addr, witness_pubkey=pub)
    us = n.discover()
    assert us.witness_pubkey == pub


def test_heartbeat_first_with_auto_bootstrap(addr, pub, cluster_key):
    """The HEARTBEAT-first flow: NodeClient sends HEARTBEAT, receives
    UNKNOWN_SOURCE, BOOTSTRAPs, retries HEARTBEAT, receives STATUS_LIST."""
    time.sleep(UNKNOWN_RATE_DELAY)  # wait for witness's UNKNOWN_SOURCE budget
    n = NodeClient(sender_id=0x01, cluster_key=cluster_key,
                   witness_addr=addr, witness_pubkey=pub)
    sl = n.heartbeat_list(b"")
    # Caller's own entry IS included (PROTOCOL.md §5.2)
    sender_ids = {e.peer_sender_id for e in sl.entries}
    assert 0x01 in sender_ids


def test_explicit_bootstrap(addr, pub, cluster_key):
    n = NodeClient(0x01, cluster_key, addr, pub)
    ack = n.bootstrap()
    assert ack.status in (0x00, 0x01)  # new or idempotent


def test_two_nodes_join_same_cluster(addr, pub, cluster_key):
    a = NodeClient(0x01, cluster_key, addr, pub)
    b = NodeClient(0x02, cluster_key, addr, pub)
    payload_a = b"role=primary" + b"\x00" * (32 - 12)
    payload_b = b"role=secondary" + b"\x00" * (32 - 14)
    a.heartbeat_list(payload_a)
    b.heartbeat_list(payload_b)
    sl = a.heartbeat_list(payload_a)
    sender_ids = {e.peer_sender_id for e in sl.entries}
    assert {0x01, 0x02}.issubset(sender_ids)


def test_status_detail_for_peer(addr, pub, cluster_key):
    a = NodeClient(0x01, cluster_key, addr, pub)
    b = NodeClient(0x02, cluster_key, addr, pub)
    payload_b = b"detail-test-value" + b"\x00" * (32 - 17)
    a.heartbeat_list(b"\x00" * 32)
    b.heartbeat_list(payload_b)
    detail = a.heartbeat_detail(peer_sender_id=0x02, own_payload=b"\x00" * 32)
    assert detail.found is True
    assert detail.target_sender_id == 0x02
    assert detail.peer_payload == payload_b


def test_self_query_appendix_a(addr, pub, cluster_key):
    """Advertise-verify-act self-query: send heartbeat with intent payload,
    confirm witness recorded it via STATUS_DETAIL self-query."""
    n = NodeClient(0x05, cluster_key, addr, pub)
    intent = b"intent=promote" + b"\x00" * (32 - 14)
    n.heartbeat_list(intent)
    detail = n.heartbeat_detail(peer_sender_id=0x05, own_payload=intent)
    assert detail.found is True
    assert detail.peer_payload == intent


def test_status_detail_for_unknown_peer(addr, pub, cluster_key):
    n = NodeClient(0x01, cluster_key, addr, pub)
    n.heartbeat_list(b"")
    detail = n.heartbeat_detail(peer_sender_id=0x99, own_payload=b"")
    assert detail.found is False
    assert detail.target_sender_id == 0x99


def test_max_payload(addr, pub, cluster_key):
    """36 blocks (1152 B) — protocol's maximum payload."""
    n = NodeClient(0x07, cluster_key, addr, pub)
    payload = b"\xCD" * 1152
    sl = n.heartbeat_list(payload)
    detail = n.heartbeat_detail(peer_sender_id=0x07, own_payload=payload)
    assert detail.found is True
    assert detail.peer_payload == payload
