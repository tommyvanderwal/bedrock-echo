"""Unit tests for the node daemon's decision logic.

Uses fake DRBD / virsh / peer-ping adapters against a real in-process
witness. No VMs, no DRBD, no network — fast.
"""
from __future__ import annotations

import socket
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from echo import crypto  # noqa: E402
from echo.witness import Witness, MTU_CAP  # noqa: E402
from node.daemon import Daemon, Config, Resource  # noqa: E402
from node.effects import FakeDrbd, FakeVirsh, FakePeerPing  # noqa: E402


def _pick_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    _, port = s.getsockname()
    s.close()
    return port


class _Loop:
    def __init__(self, w: Witness, port: int):
        self.w = w
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", port))
        self.sock.settimeout(0.1)
        self.running = True
        self.t = threading.Thread(target=self._run, daemon=True)
        self.t.start()

    def _run(self):
        while self.running:
            try:
                data, src = self.sock.recvfrom(MTU_CAP + 64)
            except socket.timeout:
                continue
            except OSError:
                return
            for reply, dst in self.w.handle_packet(data, src):
                try:
                    self.sock.sendto(reply, dst)
                except OSError:
                    pass

    def stop(self):
        self.running = False
        self.t.join(timeout=1)
        self.sock.close()


@pytest.fixture
def env():
    port = _pick_port()
    priv, pub = crypto.x25519_generate()
    w = Witness(priv)
    loop = _Loop(w, port)
    ck = crypto.random_bytes(32)
    cfg = Config(
        node_name="nodeA",
        peer_name="nodeB",
        sender_id=b"A" * 8,
        peer_sender_id=b"B" * 8,
        cluster_key=ck,
        witness_addr=("127.0.0.1", port),
        witness_x25519_pub=pub,
        peer_rings=["10.99.0.21", "10.88.0.21", "192.168.2.21"],
        resources=[Resource("vm-test-disk0", "vm-test")],
        dead_confirmations_needed=2,
    )
    yield cfg, w, loop
    loop.stop()


def test_happy_path_no_action(env):
    cfg, w, _ = env
    drbd = FakeDrbd({"vm-test-disk0": "Secondary"})
    vsh = FakeVirsh(set())
    ping = FakePeerPing(reachable={"10.99.0.21"})  # peer reachable via DRBD ring
    d = Daemon(cfg, drbd, vsh, ping)
    d.tick(time.monotonic())
    assert drbd.primary_calls == []
    assert vsh.starts == []


def test_isolated_no_takeover(env):
    """Neither peer nor witness reachable, we're Secondary → no action (freeze)."""
    cfg, w, loop = env
    loop.stop()   # take the witness offline
    drbd = FakeDrbd({"vm-test-disk0": "Secondary"})
    vsh = FakeVirsh(set())
    ping = FakePeerPing(reachable=set())   # peer also unreachable
    d = Daemon(cfg, drbd, vsh, ping)
    for _ in range(cfg.isolated_confirmations_needed + 2):
        d.tick(time.monotonic())
    # Critical: must NOT have promoted — that would be the split-brain bug.
    # And being Secondary already, no need to demote either.
    assert drbd.primary_calls == []
    assert drbd.secondary_calls == []
    assert vsh.starts == []


def test_isolated_primary_self_fences(env):
    """The split-brain trap. We're Primary, we lose both peer and witness — the
    other side may have already promoted itself. Self-fence: demote to Secondary.
    """
    cfg, w, loop = env
    loop.stop()
    drbd = FakeDrbd({"vm-test-disk0": "Primary"})
    vsh = FakeVirsh(set())
    ping = FakePeerPing(reachable=set())
    d = Daemon(cfg, drbd, vsh, ping)
    for _ in range(cfg.isolated_confirmations_needed):
        d.tick(time.monotonic())
    assert drbd.secondary_calls == ["vm-test-disk0"], \
        "isolated Primary MUST self-demote to prevent split-brain"
    assert drbd.primary_calls == []


def test_peer_dead_per_witness_triggers_takeover(env):
    """Peer unreachable on all rings, witness confirms peer silent → takeover."""
    cfg, w, _ = env
    drbd = FakeDrbd({"vm-test-disk0": "Secondary"})
    vsh = FakeVirsh(set())
    # Peer unreachable on all rings. Witness has NEVER seen the peer — that
    # means the witness's STATUS_DETAIL reply will be status=not_found, which
    # the daemon treats as "peer is dead".
    ping = FakePeerPing(reachable=set())
    d = Daemon(cfg, drbd, vsh, ping)
    for _ in range(cfg.dead_confirmations_needed):
        d.tick(time.monotonic())
    assert drbd.primary_calls == ["vm-test-disk0"]
    assert vsh.starts == ["vm-test"]


def test_peer_unreachable_from_us_but_witness_says_alive_holds(env):
    """Our rings to the peer are down, but witness sees peer heartbeat.
    Means our local network is broken, not the peer — do nothing."""
    cfg, w, loop = env
    # Simulate peer heartbeats being delivered to the witness from elsewhere:
    # bootstrap a peer client and have it heartbeat.
    from echo.node import NodeClient
    peer = NodeClient(
        sender_id=cfg.peer_sender_id, cluster_key=cfg.cluster_key,
        witness_addr=cfg.witness_addr, witness_x25519_pub=cfg.witness_x25519_pub,
    )
    peer.bootstrap(b"peer-init")
    peer.heartbeat_list(b"peer-alive")

    drbd = FakeDrbd({"vm-test-disk0": "Secondary"})
    vsh = FakeVirsh(set())
    ping = FakePeerPing(reachable=set())  # we can't see the peer at all
    d = Daemon(cfg, drbd, vsh, ping)
    for _ in range(cfg.dead_confirmations_needed + 1):
        d.tick(time.monotonic())
    assert drbd.primary_calls == [], "must not promote when witness says peer is alive"
    assert vsh.starts == []


def test_peer_returns_resets_counter(env):
    """After partial outage, if peer comes back, the dead-count resets."""
    cfg, w, _ = env
    drbd = FakeDrbd({"vm-test-disk0": "Secondary"})
    vsh = FakeVirsh(set())
    ping = FakePeerPing(reachable=set())
    d = Daemon(cfg, drbd, vsh, ping)
    # 1 tick with peer dead, dead count = 1 (threshold is 2)
    d.tick(time.monotonic())
    assert d._peer_dead_count >= 1
    # Peer comes back on mgmt ring
    ping.reachable.add("192.168.2.21")
    d.tick(time.monotonic())
    assert d._peer_dead_count == 0
    assert drbd.primary_calls == []
