"""Loopback end-to-end test: real UDP socket, real Witness, real NodeClient,
on localhost. Exercises bootstrap → heartbeat → status_list → status_detail
→ witness reboot → auto-rebootstrap → recovery.
"""
from __future__ import annotations

import os
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from echo import proto, crypto  # noqa: E402
from echo.witness import Witness, MTU_CAP  # noqa: E402
from echo.node import NodeClient  # noqa: E402


def _pick_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    _, port = s.getsockname()
    s.close()
    return port


class WitnessLoop:
    """Run a Witness on a background thread for the duration of a test."""

    def __init__(self, witness: Witness, port: int):
        self.witness = witness
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", port))
        self.sock.settimeout(0.1)
        self.running = True
        self.t = threading.Thread(target=self._loop, daemon=True)

    def start(self):
        self.t.start()
        return self

    def _loop(self):
        while self.running:
            try:
                data, src = self.sock.recvfrom(MTU_CAP + 64)
            except socket.timeout:
                continue
            except OSError:
                return
            for reply, dst in self.witness.handle_packet(data, src):
                try:
                    self.sock.sendto(reply, dst)
                except OSError:
                    pass

    def stop(self):
        self.running = False
        self.t.join(timeout=1)
        self.sock.close()


@pytest.fixture
def cluster_key():
    return crypto.random_bytes(32)


@pytest.fixture
def witness_key():
    return crypto.x25519_generate()


def test_bootstrap_then_heartbeat_list(cluster_key, witness_key):
    priv, pub = witness_key
    port = _pick_port()
    w = Witness(priv)
    loop = WitnessLoop(w, port).start()
    try:
        node = NodeClient(
            sender_id=b"A" * 8,
            cluster_key=cluster_key,
            witness_addr=("127.0.0.1", port),
            witness_x25519_pub=pub,
        )
        ack = node.bootstrap(init_payload=b"primary")
        assert ack.status == 0x00
        sl = node.heartbeat_list(own_payload=b"primary-hb")
        assert len(sl.entries) == 1
        assert sl.entries[0].peer_sender_id == b"A" * 8
    finally:
        loop.stop()


def test_two_nodes_see_each_other(cluster_key, witness_key):
    priv, pub = witness_key
    port = _pick_port()
    w = Witness(priv)
    loop = WitnessLoop(w, port).start()
    try:
        a = NodeClient(b"A" * 8, cluster_key, ("127.0.0.1", port), pub)
        b = NodeClient(b"B" * 8, cluster_key, ("127.0.0.1", port), pub)
        a.bootstrap(b"A-init")
        b.bootstrap(b"B-init")
        a.heartbeat_list(b"A-hb-1")  # seeds witness
        b.heartbeat_list(b"B-hb-1")

        detail = a.heartbeat_detail(b"B" * 8, own_payload=b"A-hb-2")
        assert detail.status == 0x00
        assert detail.target_sender_id == b"B" * 8
        assert detail.peer_payload == b"B-hb-1"

        detail_b = b.heartbeat_detail(b"A" * 8, own_payload=b"B-hb-2")
        assert detail_b.status == 0x00
        assert detail_b.peer_payload == b"A-hb-2"
    finally:
        loop.stop()


def test_unknown_source_triggers_rebootstrap(cluster_key, witness_key):
    priv, pub = witness_key
    port = _pick_port()
    w = Witness(priv)
    loop = WitnessLoop(w, port).start()
    try:
        node = NodeClient(b"A" * 8, cluster_key, ("127.0.0.1", port), pub)
        node.bootstrap()
        node.heartbeat_list()

        # Simulate a witness reboot: swap in a fresh Witness (same priv) so
        # node's cluster is unknown. Kept keyfile consistent to mimic real
        # reboot semantics.
        loop.stop()
        w2 = Witness(priv)
        loop = WitnessLoop(w2, port).start()

        # Heartbeat should trigger UNKNOWN_SOURCE → auto-rebootstrap → retry.
        sl = node.heartbeat_list(own_payload=b"hello-again")
        assert len(sl.entries) == 1
    finally:
        loop.stop()


def test_wrong_cluster_key_is_silently_dropped(cluster_key, witness_key):
    priv, pub = witness_key
    port = _pick_port()
    w = Witness(priv)
    loop = WitnessLoop(w, port).start()
    try:
        good = NodeClient(b"A" * 8, cluster_key, ("127.0.0.1", port), pub)
        good.bootstrap()
        good.heartbeat_list()

        # Attacker: same sender_id, different cluster_key. Witness should
        # not accept its HEARTBEAT (HMAC will not verify under the known
        # cluster's key).
        attacker_key = crypto.random_bytes(32)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        hb = proto.Heartbeat(
            sender_id=b"A" * 8, sequence=1, timestamp_ms=0,
            query_target_id=b"\x00" * 8, own_payload=b"pwn",
        )
        sock.sendto(hb.encode(attacker_key), ("127.0.0.1", port))
        try:
            data, _ = sock.recvfrom(MTU_CAP + 64)
        except socket.timeout:
            data = b""
        # The witness may send UNKNOWN_SOURCE (rate-limited) — anything else
        # would be a bug.
        if data:
            assert data[4] == proto.MSG_UNKNOWN_SOURCE
        sock.close()

        # Meanwhile the honest node's state is unchanged.
        sl = good.heartbeat_list()
        assert len(sl.entries) == 1
    finally:
        loop.stop()


def test_sequence_replay_dropped(cluster_key, witness_key):
    priv, pub = witness_key
    port = _pick_port()
    w = Witness(priv)
    loop = WitnessLoop(w, port).start()
    try:
        node = NodeClient(b"A" * 8, cluster_key, ("127.0.0.1", port), pub)
        node.bootstrap()
        sl = node.heartbeat_list()  # seq = some big number
        # Re-encode a HEARTBEAT with a tiny sequence: witness should drop.
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        hb = proto.Heartbeat(
            sender_id=b"A" * 8, sequence=1, timestamp_ms=0,
            query_target_id=b"\x00" * 8, own_payload=b"",
        )
        sock.sendto(hb.encode(cluster_key), ("127.0.0.1", port))
        try:
            data, _ = sock.recvfrom(MTU_CAP + 64)
            # Allowed: UNKNOWN_SOURCE if rate-limit + seq check combined.
            # Not allowed: a valid STATUS_LIST reply to a replayed packet.
            assert data[4] != proto.MSG_STATUS_LIST, "replayed seq should be dropped"
        except socket.timeout:
            pass
        sock.close()
    finally:
        loop.stop()
