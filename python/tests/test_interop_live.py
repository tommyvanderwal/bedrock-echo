"""Live cross-language interop: talk to a running Rust witness binary
from the Python NodeClient. Skipped if the binary isn't available or
if the BEDROCK_ECHO_WITNESS_ADDR env var isn't set.

Usage (manual):
    # start the Rust binary somewhere, then:
    BEDROCK_ECHO_WITNESS_ADDR=127.0.0.1:17337 \
    BEDROCK_ECHO_WITNESS_PUB=<hex-of-witness-pub> \
    PYTHONPATH=python python3 -m pytest python/tests/test_interop_live.py -v
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from echo import proto, crypto  # noqa: E402
from echo.node import NodeClient  # noqa: E402


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
    # Shared across tests in this module so re-bootstrapping the same
    # sender_id is idempotent (see PROTOCOL.md §4.6). Production node
    # deployments pick cluster_key once per cluster, not per test.
    return crypto.random_bytes(32)


def test_bootstrap_ok(addr, pub, cluster_key):
    n = NodeClient(
        sender_id=b"A" * 8, cluster_key=cluster_key,
        witness_addr=addr, witness_x25519_pub=pub,
    )
    ack = n.bootstrap(init_payload=b"hello-rust")
    assert ack.status == 0x00


def test_heartbeat_list_and_detail(addr, pub, cluster_key):
    a = NodeClient(b"A" * 8, cluster_key, addr, pub)
    b = NodeClient(b"B" * 8, cluster_key, addr, pub)
    a.bootstrap(b"A-init")
    b.bootstrap(b"B-init")
    a.heartbeat_list(b"A-hb")   # seed witness with A's payload
    b.heartbeat_list(b"B-hb")   # seed witness with B's payload

    detail = a.heartbeat_detail(b"B" * 8, b"A-hb-2")
    assert detail.status == 0x00
    assert detail.peer_payload == b"B-hb"

    sl = a.heartbeat_list(b"A-hb-3")
    ids = {e.peer_sender_id for e in sl.entries}
    assert b"A" * 8 in ids
    assert b"B" * 8 in ids


def test_unknown_sender_gets_unknown_source_reply(addr, pub, cluster_key):
    """A client that heartbeats without ever bootstrapping should get the
    UNKNOWN_SOURCE auto-rebootstrap path from NodeClient, which recovers."""
    n = NodeClient(b"C" * 8, cluster_key, addr, pub)
    # Don't call bootstrap; heartbeat_list should auto-bootstrap on UNKNOWN_SOURCE
    sl = n.heartbeat_list(b"C-hb")
    # Either the list is empty (fresh cluster) or contains C.
    ids = {e.peer_sender_id for e in sl.entries}
    assert ids.issubset({b"C" * 8, b"A" * 8, b"B" * 8})
