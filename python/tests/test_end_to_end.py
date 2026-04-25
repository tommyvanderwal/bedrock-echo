"""End-to-end tests: NodeClient ↔ Witness over real UDP loopback.

Spins up the witness in a thread on a random local port, exercises the
full HEARTBEAT-first / fallback-to-BOOTSTRAP / DISCOVER flows, then shuts
down cleanly.
"""
from __future__ import annotations

import socket
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from echo import proto, crypto, witness, node  # noqa: E402


CK = bytes(range(0x10, 0x30))


def _bind_witness_socket() -> tuple[socket.socket, int]:
    """Bind a UDP socket on 127.0.0.1 with a kernel-assigned port."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    return s, s.getsockname()[1]


def _run_witness(w: witness.Witness, sock: socket.socket, stop: threading.Event):
    sock.settimeout(0.1)
    while not stop.is_set():
        try:
            data, src = sock.recvfrom(proto.MTU_CAP + 64)
        except (socket.timeout, BlockingIOError):
            continue
        for reply, dst in w.handle_packet(data, src):
            sock.sendto(reply, dst)


@pytest.fixture
def live_witness():
    """Start a witness in a background thread; yield (witness, addr, pubkey)."""
    sock, port = _bind_witness_socket()
    priv = bytes([0xAA] * 32)
    w = witness.Witness(priv)
    stop = threading.Event()
    t = threading.Thread(target=_run_witness, args=(w, sock, stop), daemon=True)
    t.start()
    try:
        yield w, ("127.0.0.1", port), w.pub
    finally:
        stop.set()
        t.join(timeout=1.0)
        sock.close()


def test_e2e_discover_returns_pubkey(live_witness):
    w, addr, pub = live_witness
    n = node.NodeClient(sender_id=0x01, cluster_key=CK,
                        witness_addr=addr, witness_pubkey=pub)
    us = n.discover()
    assert us.witness_pubkey == pub


def test_e2e_heartbeat_first_with_unknown_source_recovery(live_witness):
    """First HEARTBEAT triggers UNKNOWN_SOURCE; NodeClient bootstraps then retries."""
    w, addr, pub = live_witness
    n = node.NodeClient(sender_id=0x01, cluster_key=CK,
                        witness_addr=addr, witness_pubkey=pub)
    sl = n.heartbeat_list(b"")
    assert len(sl.entries) == 1
    assert sl.entries[0].peer_sender_id == 0x01
    # Witness should now have one cluster, one node
    assert len(w.clusters) == 1
    assert len(w.nodes) == 1


def test_e2e_two_nodes_join_same_cluster(live_witness):
    w, addr, pub = live_witness
    a = node.NodeClient(0x01, CK, addr, pub)
    b = node.NodeClient(0x02, CK, addr, pub)
    a.heartbeat_list()
    b.heartbeat_list()
    sl = a.heartbeat_list()
    sender_ids = {e.peer_sender_id for e in sl.entries}
    assert sender_ids == {0x01, 0x02}


def test_e2e_status_detail_for_peer(live_witness):
    w, addr, pub = live_witness
    a = node.NodeClient(0x01, CK, addr, pub)
    b = node.NodeClient(0x02, CK, addr, pub)
    a.heartbeat_list(b"\xAA" * 32)
    payload_b = b"role=primary" + b"\x00" * (32 - 12)
    b.heartbeat_list(payload_b)
    # A queries B's detail
    sd = a.heartbeat_detail(peer_sender_id=0x02, own_payload=b"\x00" * 32)
    assert sd.found is True
    assert sd.target_sender_id == 0x02
    assert sd.peer_payload == payload_b


def test_e2e_self_query_appendix_a_pattern(live_witness):
    """Advertise-verify-act: send heartbeat with intent payload, then
    self-query to confirm witness recorded it before acting."""
    w, addr, pub = live_witness
    a = node.NodeClient(0x01, CK, addr, pub)
    intent = b"intent=promote-R" + b"\x00" * (32 - 16)
    # Step 2: advertise
    a.heartbeat_list(intent)
    # Step 3: self-query to verify
    detail = a.heartbeat_detail(peer_sender_id=0x01, own_payload=intent)
    # The self-query's HB will have replaced the witness-stored payload with
    # `intent` again, so:
    assert detail.found is True
    assert detail.peer_payload == intent
    # Real act-decision logic would happen at the application layer.


def test_e2e_explicit_bootstrap_roundtrip(live_witness):
    w, addr, pub = live_witness
    a = node.NodeClient(0x01, CK, addr, pub)
    ack = a.bootstrap()
    assert ack.status == 0x00  # new
    # Re-bootstrap is idempotent
    ack2 = a.bootstrap()
    assert ack2.status == 0x01


def test_e2e_aead_protects_payload_confidentiality(live_witness):
    """Sniff the wire and confirm payload bytes are not in plaintext."""
    w, addr, pub = live_witness
    n = node.NodeClient(0x01, CK, addr, pub)
    n.heartbeat_list()  # establish cluster
    # Build a heartbeat with a recognizable plaintext signature
    sentinel = b"PLAINTEXT-SENTINEL-DO-NOT-LEAK!\x00"  # 32 B
    hb = proto.Heartbeat(sender_id=0x01, timestamp_ms=int(time.time() * 1000) + 1000,
                         query_target_id=0xFF, own_payload=sentinel)
    wire = hb.encode(CK)
    # The header is plaintext (we don't expect to find sentinel there).
    # The payload + tag is encrypted.
    assert sentinel not in wire
    # Decoding works fine with the right key
    decoded = proto.decode_heartbeat(wire, CK)
    assert decoded.own_payload == sentinel
