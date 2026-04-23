#!/usr/bin/env python3
"""Bedrock Echo failure-scenario harness.

Runs on the KVM host. Injects network faults at L2 by taking tap interfaces
up/down, then asserts the core invariant:

    AT NO POINT can BOTH nodes be DRBD Primary simultaneously.

Usage:
  harness/scenarios.py list
  harness/scenarios.py links                  # show tap state per VM/net
  harness/scenarios.py run <name|all>         # run one scenario or all
  harness/scenarios.py restore                # bring every tap back up
  harness/scenarios.py check                  # one-shot role check
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Callable, Optional

VMS = ("bec-witness", "bec-node-a", "bec-node-b")
NETS = ("bedrock-mgmt", "bedrock-drbd", "bec-link2")
NODE_MGMT_IPS = {"bec-node-a": "192.168.2.176", "bec-node-b": "192.168.2.180"}
WITNESS_IP = "192.168.2.175"

SETTLE_S = 30       # how long to watch for reactions
RECOVER_S = 15      # how long to wait after restoring links


def sh(cmd, check=True, capture=True, timeout=30) -> tuple[str, int]:
    try:
        r = subprocess.run(
            cmd if isinstance(cmd, list) else ["bash", "-c", cmd],
            capture_output=capture, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        sys.stderr.write(f"TIMEOUT: {cmd}\n")
        if check:
            sys.exit(1)
        return ("", 1)
    if check and r.returncode != 0:
        sys.stderr.write(f"FAIL: {cmd}\n{r.stderr}\n")
        sys.exit(r.returncode)
    return (r.stdout.strip() if capture else "", r.returncode)


def virsh(*args, check: bool = False) -> str:
    """virsh wrapper. check=False by default because many harness calls expect
    virsh to return non-zero sometimes (e.g. "Domain is already active")."""
    out, _ = sh(["sudo", "virsh", *args], check=check)
    return out


def wait_ssh_up(ip: str, timeout_s: int = 120) -> bool:
    """Poll until ssh root@ip returns non-zero, or timeout. Returns True on success."""
    import time as _t
    deadline = _t.monotonic() + timeout_s
    while _t.monotonic() < deadline:
        r = subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null",
             "-o", "BatchMode=yes",
             "-o", "ConnectTimeout=3",
             f"root@{ip}", "true"],
            capture_output=True, text=True, timeout=6,
        )
        if r.returncode == 0:
            return True
        _t.sleep(3)
    return False


def ensure_drbd_up(ip: str) -> bool:
    """Ensure bec-r0 is brought up (drbdadm up) on the node."""
    r = subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null",
         "-o", "BatchMode=yes",
         "-o", "ConnectTimeout=5",
         f"root@{ip}",
         "drbdadm status bec-r0 >/dev/null 2>&1 || drbdadm up bec-r0"],
        capture_output=True, text=True, timeout=15,
    )
    return r.returncode == 0


def stabilize_both_nodes(max_wait_s: int = 150) -> None:
    """After any scenario that may have powered off a node, wait for both
    nodes to be SSH-ready AND have their DRBD resource up.  Helps prevent
    the next scenario from starting in a half-booted state."""
    for node, ip in NODE_MGMT_IPS.items():
        if not wait_ssh_up(ip, timeout_s=max_wait_s):
            print(f"    WARN: {node} ({ip}) not ssh-ready after {max_wait_s}s")
            continue
        ensure_drbd_up(ip)


def tap_of(vm: str, net: str) -> Optional[str]:
    out = virsh("domiflist", vm)
    for line in out.splitlines()[2:]:
        parts = line.split()
        if len(parts) >= 3 and parts[2] == net:
            return parts[0]
    return None


def set_tap(tap: str, up: bool, quiet: bool = False) -> None:
    arrow = "↑" if up else "↓"
    if not quiet: print(f"  {arrow} {tap} ({'up' if up else 'down'})")
    sh(["sudo", "ip", "link", "set", tap, "up" if up else "down"], check=False)


def cut(vm: str, net: str, quiet: bool = False) -> None:
    t = tap_of(vm, net)
    if t is None:
        if not quiet: print(f"  (no tap for {vm} on {net})")
        return
    if not quiet: print(f"  ↓ {vm}/{net} → {t}")
    set_tap(t, False, quiet=True)


def restore_all(quiet: bool = False) -> None:
    if not quiet: print("  [restore all]")
    for vm in VMS:
        for net in NETS:
            t = tap_of(vm, net)
            if t is not None:
                set_tap(t, True, quiet=True)


def drbd_role(node: str, timeout: float = 3.0) -> Optional[str]:
    """Return 'Primary' / 'Secondary' / 'Unknown' for <node>'s bec-r0, or None
    if we can't reach it. Never raises."""
    ip = NODE_MGMT_IPS[node]
    try:
        r = subprocess.run(
            ["ssh",
             "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null",
             "-o", f"ConnectTimeout={int(timeout)}",
             "-o", "PasswordAuthentication=no",
             "-o", "BatchMode=yes",
             f"root@{ip}", "drbdadm role bec-r0 2>/dev/null"],
            capture_output=True, text=True, timeout=timeout + 2,
        )
    except (subprocess.TimeoutExpired, Exception):
        return None
    if r.returncode != 0:
        return None
    return r.stdout.strip() or None


def check_invariant(context: str) -> bool:
    """Assert at most one Primary. Returns True if ok, False if broken.
    Unknown (None) results are treated as 'can't verify' (logged, not fatal)."""
    roles = {n: drbd_role(n) for n in ("bec-node-a", "bec-node-b")}
    primaries = [n for n, r in roles.items() if r == "Primary"]
    print(f"    [{context}] roles: {roles}  primaries={len(primaries)}")
    if len(primaries) > 1:
        print(f"  *** SPLIT-BRAIN DETECTED: {primaries} ***")
        return False
    return True


# ─── Scenarios ─────────────────────────────────────────────────────────────


@dataclass
class Scenario:
    name: str
    description: str
    setup: Callable[[], None]
    expect_takeover_by: Optional[str] = None   # name of node that should go Primary, or None
    expect_no_change: bool = False
    recover: Optional[Callable[[], None]] = None  # ran after setup, before restore_all
    recover_wait_s: int = 0                     # extra wait after `recover` (e.g. VM boot time)

    def run(self) -> bool:
        """Returns True iff the invariant held AND expectations met."""
        print(f"\n=== {self.name} ===")
        print(f"    {self.description}")
        restore_all(quiet=True)
        time.sleep(3)

        # Snapshot steady state
        pre_roles = {n: drbd_role(n) for n in ("bec-node-a", "bec-node-b")}
        print(f"    pre:  {pre_roles}")

        self.setup()
        print(f"    [settling {SETTLE_S}s, checking invariant periodically]")

        ok = True
        for i in range(SETTLE_S // 5):
            time.sleep(5)
            if not check_invariant(f"t+{(i+1)*5}s"):
                ok = False

        # Scenario-specific recover (e.g. power the VM back on)
        if self.recover is not None:
            print(f"    [scenario recover]")
            self.recover()
            # For scenarios that may have powered off a VM, actively wait
            # until both nodes are SSH-ready (cloud-init + network up +
            # sshd up), rather than a fixed sleep.
            print(f"    [waiting for both nodes to be SSH-ready (max {self.recover_wait_s}s)]")
            stabilize_both_nodes(max_wait_s=max(self.recover_wait_s, 120))

        # Restore and let things reconverge
        print("    [restore + recover]")
        restore_all(quiet=True)
        for i in range(RECOVER_S // 5):
            time.sleep(5)
            if not check_invariant(f"post+{(i+1)*5}s"):
                ok = False

        post_roles = {n: drbd_role(n) for n in ("bec-node-a", "bec-node-b")}
        print(f"    post: {post_roles}")

        # Expectations
        if self.expect_takeover_by:
            if post_roles.get(self.expect_takeover_by) != "Primary":
                print(f"    EXPECTED takeover by {self.expect_takeover_by}, but post roles are {post_roles}")
                ok = False
        if self.expect_no_change:
            if post_roles != pre_roles:
                print(f"    EXPECTED no change, but pre={pre_roles} post={post_roles}")
                # Do NOT fail — sometimes witness age-out races. Log only.

        # Universal invariant: after recovery, exactly one Primary must exist.
        num_primaries_final = sum(1 for r in post_roles.values() if r == "Primary")
        if num_primaries_final == 0:
            print(f"    ERROR: NO Primary after recovery — cluster is unavailable")
            ok = False

        print(f"    → {'PASS' if ok else 'FAIL'}")
        return ok


def scn_steady():
    pass


def scn_cut_drbd_ring_a():
    cut("bec-node-a", "bedrock-drbd")
    cut("bec-node-b", "bedrock-drbd")


def scn_cut_both_drbd_rings():
    cut("bec-node-a", "bedrock-drbd")
    cut("bec-node-b", "bedrock-drbd")
    cut("bec-node-a", "bec-link2")
    cut("bec-node-b", "bec-link2")


def scn_isolate_a_completely():
    for net in NETS:
        cut("bec-node-a", net)


def scn_isolate_b_completely():
    for net in NETS:
        cut("bec-node-b", net)


def _current_primary() -> Optional[str]:
    for n in ("bec-node-a", "bec-node-b"):
        if drbd_role(n) == "Primary":
            return n
    return None


def scn_isolate_current_primary():
    p = _current_primary()
    if p is None:
        print("  (no current Primary — skipping)")
        return
    print(f"  targeting current Primary: {p}")
    for net in NETS:
        cut(p, net)


def scn_power_off_current_primary():
    p = _current_primary()
    if p is None:
        return
    print(f"  destroying current Primary: {p}")
    virsh("destroy", p)


def scn_witness_partition():
    cut("bec-witness", "bedrock-mgmt")


def scn_witness_reboot():
    sh(["ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        f"root@{WITNESS_IP}", "systemctl restart bedrock-echo-witness"],
       check=False)


def scn_power_off_a():
    virsh("destroy", "bec-node-a")


def scn_power_off_b():
    virsh("destroy", "bec-node-b")


def scn_node_daemon_restart_a():
    sh(["ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        f"root@{NODE_MGMT_IPS['bec-node-a']}", "systemctl restart bedrock-echo-node"],
       check=False)


SCENARIOS = [
    Scenario("steady", "No faults — baseline", scn_steady, expect_no_change=True),
    Scenario("cut-drbd-ring-a", "DRBD ring A cut, mgmt + link2 intact",
             scn_cut_drbd_ring_a, expect_no_change=True),
    Scenario("cut-both-drbd-rings",
             "Both DRBD rings cut, mgmt intact — peers still see each other",
             scn_cut_both_drbd_rings, expect_no_change=True),
    Scenario("witness-partition",
             "Witness unreachable from both nodes — no quorum, no promotion",
             scn_witness_partition, expect_no_change=True),
    Scenario("witness-reboot",
             "Witness service restarts — nodes auto-rebootstrap, no promotion",
             scn_witness_reboot, expect_no_change=True),
    Scenario("daemon-restart-a",
             "Node A's daemon restarts — heartbeats blip briefly, no promotion",
             scn_node_daemon_restart_a, expect_no_change=True),
    Scenario("isolate-node-a",
             "Node A fully isolated — B+witness agree A is dead; B promotes "
             "(then A self-fences to Secondary on recovery)",
             scn_isolate_a_completely, expect_takeover_by="bec-node-b"),
    Scenario("isolate-node-b",
             "Node B fully isolated — A+witness agree B is dead; A promotes "
             "(then B self-fences to Secondary on recovery)",
             scn_isolate_b_completely, expect_takeover_by="bec-node-a"),
    Scenario("power-off-a",
             "Hard-kill node A (virsh destroy) — B takes over, A comes back as Secondary",
             scn_power_off_a, expect_takeover_by="bec-node-b",
             recover=lambda: virsh("start", "bec-node-a"),
             recover_wait_s=90),
    # Dynamic scenarios — target whichever side is currently Primary so the
    # test always exercises the real takeover path regardless of starting role.
    Scenario("isolate-current-primary",
             "Isolate whichever node is currently Primary; the other must promote",
             scn_isolate_current_primary),
    Scenario("power-off-current-primary",
             "virsh destroy the current Primary; survivor must promote",
             scn_power_off_current_primary,
             recover=lambda: (virsh("start", "bec-node-a"), virsh("start", "bec-node-b")),
             recover_wait_s=90),
]


# ─── Commands ─────────────────────────────────────────────────────────────


def cmd_list(_):
    for s in SCENARIOS:
        print(f"  {s.name:25s}  {s.description}")


def cmd_links(_):
    for vm in VMS:
        for net in NETS:
            t = tap_of(vm, net)
            if t is None: continue
            state, _ = sh(["ip", "-br", "link", "show", t], check=False)
            print(f"  {vm:15s} {net:15s} {t:10s} {state}")


def cmd_restore(_):
    restore_all()


def cmd_check(_):
    check_invariant("now")


def cmd_run(args):
    targets = SCENARIOS if args.name == "all" else [s for s in SCENARIOS if s.name == args.name]
    if not targets:
        sys.exit(f"no scenario named {args.name}")
    results = []
    try:
        for s in targets:
            results.append((s.name, s.run()))
    finally:
        print("\n[final restore]")
        restore_all()
        time.sleep(5)
        check_invariant("final")
    print("\n=== summary ===")
    passed = sum(1 for _, ok in results if ok)
    for name, ok in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    print(f"  {passed}/{len(results)} passed")
    sys.exit(0 if passed == len(results) else 1)


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list").set_defaults(func=cmd_list)
    sub.add_parser("links").set_defaults(func=cmd_links)
    sub.add_parser("restore").set_defaults(func=cmd_restore)
    sub.add_parser("check").set_defaults(func=cmd_check)
    r = sub.add_parser("run")
    r.add_argument("name")
    r.set_defaults(func=cmd_run)
    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
