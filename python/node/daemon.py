"""Bedrock Echo node daemon.

One daemon per cluster node. Loops:
  1. Heartbeat to the witness (detail query for peer).
  2. TCP-ping peer on mgmt + drbd + link2 rings.
  3. Evaluate quorum (self + peer-via-any-ring + witness-confirms-peer-alive).
  4. If peer unreachable on all rings AND witness confirms peer dead AND
     we're still Secondary with VM not running: promote + start.
  5. If we ever can't reach witness AND can't reach peer: freeze (no action).

Decision logic matches PROTOCOL.md's intent: never create a split-brain.
"""
from __future__ import annotations

import logging
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Allow `python/node/daemon.py` to be run as a script with PYTHONPATH=python
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from echo import crypto
from echo.node import NodeClient
from echo import proto
from node.effects import (
    DrbdAdapter, VirshAdapter, PeerPing,
    RealDrbd, RealVirsh, RealPeerPing,
)

log = logging.getLogger("echo.node.daemon")


HEARTBEAT_INTERVAL_S = 3.0
PEER_CHECK_INTERVAL_S = 2.0
DEAD_CONFIRMATIONS_NEEDED = 3
ISOLATED_CONFIRMATIONS_NEEDED = 3   # after N ticks of ISOLATED, a Primary self-demotes
WITNESS_TIMEOUT_S = 10   # peer is "dead per witness" if witness saw >10s ago


@dataclass
class Resource:
    """One DRBD resource + the VM it backs."""
    drbd_resource: str
    vm_name: str


@dataclass
class Config:
    node_name: str
    peer_name: str
    sender_id: int            # 0x00..0xFE  (PROTOCOL.md §2)
    peer_sender_id: int       # 0x00..0xFE
    cluster_key: bytes        # 32 bytes
    witness_addr: tuple[str, int]
    witness_pubkey: bytes     # 32 bytes — the witness's X25519 public key
    # All of {mgmt_ip, drbd_ip, link2_ip} are the PEER's addresses on each ring.
    peer_rings: list[str]
    resources: list[Resource]
    dry_run: bool = False
    heartbeat_interval_s: float = HEARTBEAT_INTERVAL_S
    peer_check_interval_s: float = PEER_CHECK_INTERVAL_S
    dead_confirmations_needed: int = DEAD_CONFIRMATIONS_NEEDED
    isolated_confirmations_needed: int = ISOLATED_CONFIRMATIONS_NEEDED


@dataclass
class Daemon:
    cfg: Config
    drbd: DrbdAdapter
    virsh: VirshAdapter
    peer_ping: PeerPing
    _peer_dead_count: int = 0
    _isolated_count: int = 0
    _takeover_done: bool = False
    _last_heartbeat: float = 0.0
    _client: Optional[NodeClient] = None

    def __post_init__(self):
        self._client = NodeClient(
            sender_id=self.cfg.sender_id,
            cluster_key=self.cfg.cluster_key,
            witness_addr=self.cfg.witness_addr,
            witness_pubkey=self.cfg.witness_pubkey,
        )

    def tick(self, now: float) -> None:
        """One iteration of the decision loop. Tests call this directly."""
        # Emit own payload describing DRBD state for peer consumption
        own_payload = self._describe_self()

        # 1. Peer reachability across all rings
        peer_reachable, ring = self._peer_reachable_anywhere()

        # 2. Witness verdict on peer
        witness_status = self._query_witness(own_payload)
        # witness_status: None = witness unreachable
        #                 {"alive": bool, "last_seen_s": int} = peer visibility
        witness_reachable = witness_status is not None
        witness_says_dead = (
            witness_reachable
            and (witness_status is None or not witness_status.get("alive", False))
        )

        # 3. Quorum math (self always counts as 1)
        # Reset isolation counter on ANY external signal (peer OR witness)
        if peer_reachable or witness_reachable:
            self._isolated_count = 0

        if peer_reachable:
            if self._peer_dead_count > 0:
                log.info("peer %s reachable again via %s (was dead %d ticks)",
                         self.cfg.peer_name, ring, self._peer_dead_count)
            self._peer_dead_count = 0
            self._takeover_done = False
            return

        if witness_reachable and witness_says_dead:
            if not self._takeover_done:
                self._peer_dead_count += 1
                log.warning(
                    "peer %s unreachable on all rings AND witness says dead (%d/%d)",
                    self.cfg.peer_name, self._peer_dead_count,
                    self.cfg.dead_confirmations_needed,
                )
                if self._peer_dead_count >= self.cfg.dead_confirmations_needed:
                    self._takeover()
                    self._takeover_done = True
                    self._peer_dead_count = 0
            return

        if witness_reachable and not witness_says_dead:
            log.info(
                "peer %s unreachable from us but witness sees it alive — "
                "network issue on our side, holding",
                self.cfg.peer_name,
            )
            self._peer_dead_count = 0
            return

        # Neither peer nor witness reachable → ISOLATED.
        # Staying Primary here is the classic split-brain foot-gun: the other
        # side may have already concluded we're dead and promoted itself. If
        # we're currently Primary and stay isolated for more than
        # `isolated_confirmations_needed` ticks, self-fence: demote to
        # Secondary. Demotion is idempotent, reversible, and safe — a
        # survivor Primary that comes back into contact will stay Primary
        # and we'll converge without split-brain.
        self._peer_dead_count = 0
        self._isolated_count += 1
        log.warning(
            "ISOLATED: peer %s unreachable, witness unreachable — no quorum (%d/%d)",
            self.cfg.peer_name, self._isolated_count,
            self.cfg.isolated_confirmations_needed,
        )
        if self._isolated_count >= self.cfg.isolated_confirmations_needed:
            self._self_fence_if_primary()

    def _self_fence_if_primary(self) -> None:
        any_primary = False
        for r in self.cfg.resources:
            role = self.drbd.role(r.drbd_resource)
            if role == "Primary":
                any_primary = True
                log.warning("SELF-FENCE: demoting %s (we are isolated and currently Primary)",
                            r.drbd_resource)
                if self.cfg.dry_run:
                    continue
                if not self.drbd.secondary(r.drbd_resource):
                    log.error("failed to demote %s", r.drbd_resource)
        if not any_primary:
            log.info("isolated but already Secondary — nothing to fence")

    def run_forever(self) -> None:
        """Production loop. Tests use `tick` directly."""
        log.info("bedrock-echo node daemon starting: node=%s peer=%s",
                 self.cfg.node_name, self.cfg.peer_name)
        while True:
            now = time.monotonic()
            try:
                self.tick(now)
            except Exception:
                log.exception("tick failed")
            time.sleep(self.cfg.peer_check_interval_s)

    # ── internals ──

    def _describe_self(self) -> bytes:
        """Compact opaque payload describing our DRBD state. The witness stores
        this verbatim and serves it to the peer on STATUS_DETAIL. Block-
        granular per PROTOCOL.md §4.1: pad to a 32 B multiple, cap at 1152 B."""
        parts = []
        for r in self.cfg.resources:
            parts.append(f"{r.drbd_resource}:{self.drbd.role(r.drbd_resource)}")
        payload = ",".join(parts).encode()
        # Cap, then round up to a 32-byte block boundary with zero padding.
        payload = payload[:proto.PAYLOAD_MAX_BYTES]
        pad = (-len(payload)) % proto.PAYLOAD_BLOCK_SIZE
        return payload + b"\x00" * pad

    def _peer_reachable_anywhere(self) -> tuple[bool, Optional[str]]:
        for ring in self.cfg.peer_rings:
            if self.peer_ping.ping(ring, 22, 2.0):
                return True, ring
        return False, None

    def _query_witness(self, own_payload: bytes) -> Optional[dict]:
        """Send HEARTBEAT, get STATUS_DETAIL on peer. Returns a small dict or
        None if the witness is unreachable."""
        try:
            sd = self._client.heartbeat_detail(self.cfg.peer_sender_id, own_payload)
        except Exception as e:
            log.debug("witness unreachable: %s", e)
            return None
        if not sd.found:
            # Witness doesn't know the peer — treat as dead (never seen or aged out).
            return {"alive": False, "last_seen_s": None}
        last_seen_s = sd.peer_seen_ms_ago / 1000.0
        return {"alive": last_seen_s <= WITNESS_TIMEOUT_S, "last_seen_s": last_seen_s}

    def _takeover(self) -> None:
        log.warning("QUORUM (self+witness) — initiating takeover")
        running = self.virsh.running_vms() if any(r.vm_name for r in self.cfg.resources) else set()
        for r in self.cfg.resources:
            role = self.drbd.role(r.drbd_resource)
            if role != "Secondary":
                log.info("resource %s already %s, skipping", r.drbd_resource, role)
                continue
            log.warning("promoting %s", r.drbd_resource)
            if self.cfg.dry_run:
                continue
            if not self.drbd.primary(r.drbd_resource):
                log.error("failed to promote %s", r.drbd_resource)
                continue
            if r.vm_name and r.vm_name not in running:
                log.warning("starting VM %s", r.vm_name)
                if not self.virsh.start(r.vm_name):
                    log.error("failed to start %s", r.vm_name)


def build_real_daemon(cfg: Config) -> Daemon:
    return Daemon(
        cfg=cfg,
        drbd=RealDrbd(),
        virsh=RealVirsh(),
        peer_ping=RealPeerPing(),
    )
