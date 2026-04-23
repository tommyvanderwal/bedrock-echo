# Bedrock Echo — v0.001 Validation Report

**Date:** 2026-04-23
**Status:** Pilot validated. Protocol and implementation ready for ESP32 port.

---

## Summary

The Bedrock Echo v0.001 pilot has been validated end-to-end on a local KVM
testbed. The witness protocol is implemented in Rust (ESP32-ready core) and
Python (reference), with byte-exact interoperability and a live network
test. The DRBD+node+witness stack has been exercised under 11 failure
scenarios and a data-integrity failover test. No split-brain has been
observed under any condition; no committed write has been lost across a
forced failover.

---

## Test suites

### Python — 48 tests

```
python/tests/test_protocol.py    — 16 unit tests (encode/decode/auth/replay)
python/tests/test_vectors.py     — 18 interop vector tests
python/tests/test_end_to_end.py  —  5 loopback tests (real UDP, real witness)
python/tests/test_node_daemon.py —  6 decision-logic tests (mocked DRBD)
python/tests/test_interop_live.py —  3 live VM tests (Rust witness ↔ Python)
─────────────────────────────────────────────────────────────────────────────
                                    48 passed
```

### Rust — 13 tests

```
crates/bedrock-echo-proto/tests/test_vectors.rs — 13 interop tests
  9 encode-matches tests (Rust writes bytes == Python writes bytes)
  4 decode-matches tests (Rust parses same bytes Python parsed)
─────────────────────────────────────────────────────────────────────────────
                                    13 passed
```

### Scenario harness — 11 scenarios

All 11 scenarios assert the invariant **at no point can both nodes be DRBD
Primary simultaneously**, checked every 5 seconds during settlement and
recovery:

| # | Scenario | Description | Result |
|---|---|---|---|
| 1 | steady | No faults, baseline | PASS |
| 2 | cut-drbd-ring-a | DRBD ring A cut, mgmt+link2 intact | PASS |
| 3 | cut-both-drbd-rings | Both DRBD rings cut, mgmt intact | PASS |
| 4 | witness-partition | Witness unreachable from both nodes | PASS |
| 5 | witness-reboot | Witness restart mid-operation | PASS |
| 6 | daemon-restart-a | Node A's daemon restart | PASS |
| 7 | isolate-node-a | A all 3 rings cut — B takes over, A self-fences | PASS |
| 8 | isolate-node-b | B all 3 rings cut — A takes over, B self-fences | PASS |
| 9 | power-off-a | `virsh destroy` node-a, wait, bring back | PASS |
| 10 | isolate-current-primary | Dynamic — target whoever is Primary | PASS |
| 11 | power-off-current-primary | Dynamic — destroy current Primary | PASS |

### Data integrity — end-to-end failover

```
1. Write 4KB random pattern to /dev/drbd0 on Primary (sha256=485b2796...)
2. Read-back on Primary → hash match          ✓
3. Cut ALL 3 rings on Primary (full isolation)
4. Survivor detects + promotes via --force    ✓
5. Read pattern from NEW Primary → hash match ✓  (no data lost)
6. Restore ex-Primary's rings
7. Ex-Primary self-fences to Secondary        ✓  (no role split)
8. DRBD reconnects, both UpToDate             ✓
```

### Stress — 10 rapid cut/restore cycles

10 iterations of (cut DRBD ring tap, 4s pause, restore, 6s pause). After
each cut and each restore, role invariant verified. **0 split-brains.**

---

## DRBD fail-safe configuration

The Bedrock Echo design only works if DRBD can't lie about data being
committed. The following `/etc/drbd.d/bec-r0.res` options make this true:

```
options {
    quorum majority;          # 2-of-2 in a 2-node cluster
    on-no-quorum suspend-io;  # lose peer → kernel blocks writes
}
net {
    protocol C;               # synchronous — both sides ack before client sees OK
    after-sb-1pri discard-secondary;  # reconnect after self-fence: Secondary discards
}
```

### Verified fail-safe behaviour

```
# shell A (on Primary)
dd if=/dev/zero of=/dev/drbd0 bs=4K count=1 oflag=direct   # completes in 3ms

# shell B (on host)
sudo ip link set <drbd-tap> down                            # cut peer link

# shell A
timeout 10 dd if=/dev/zero of=/dev/drbd0 bs=4K count=1 oflag=direct
# dd enters D-state (uninterruptible kernel sleep)
# exit=124 — timeout SIGKILL'd dd; write never acknowledged
```

**Corollary:** any write the app saw "success" for is either on both sides
already, or the link was still up when it was issued and will be replicated.
No write that the application has been told "OK" can exist only on one side.

---

## Split-brain prevention chain

Defense in depth, from kernel up:

1. **Kernel layer — DRBD quorum + protocol C**: Primary blocks writes when
   peer is unreachable. Writes cannot complete locally. This is the
   primary guard.
2. **Daemon layer — self-fence**: isolated Primary demotes to Secondary
   after 3 confirmations (~24s). Defense-in-depth: even if some edge case
   let DRBD accept a local write, the role collision is prevented on
   reconnect.
3. **Witness layer — Bedrock Echo protocol**: external tiebreaker. Survivor
   only promotes when witness confirms peer is dead. Never promote on pure
   local information.
4. **DRBD recovery layer — `after-sb-1pri discard-secondary`**: if any
   residual divergence makes it through, Secondary discards its
   non-replicated bits on reconnection. No manual intervention.

---

## Codebase footprint

| Component | Lines |
|---|---|
| `PROTOCOL.md` (spec) | 634 |
| Rust witness core (`no_std`-ready) | 749 |
| Rust witness binary (std shim) | 522 |
| Python protocol impl | 662 |
| Python witness daemon + server | 446 |
| Python node daemon + effects + CLI | 497 |
| **Total source** | **~3500** |

Rust witness binary, stripped, statically compiled for x86-64 Linux: **414 KB**.
Dependencies: libc + libgcc (no exotic runtime).

---

## Runtime topology

```
                       LAN (192.168.2.0/24, br0)
          ┌────────────┬───────────────────┬───────────────┐
          │            │                   │               │
     bec-witness    bec-node-a       bec-node-b        other LAN hosts
     .2.175          .2.176           .2.180
          │            │                   │
          │            └──(eth1: 10.99.0.20)───(eth1: 10.99.0.21)──┐
          │            │   bedrock-drbd (isolated, DRBD ring A)     │
          │            │                                            │
          │            └──(eth2: 10.88.0.20)───(eth2: 10.88.0.21)──┘
          │                bec-link2 (isolated, heartbeat ring B)
          │
     Rust witness binary (414 KB, systemd unit)
     RAM-only state
     X25519 pubkey on /var/lib/bedrock-echo/witness.x25519.key
```

Nodes: Python daemon as systemd unit `bedrock-echo-node.service` on each,
heartbeating the witness every 3s (plus peer pings on all 3 rings),
Primary/Secondary roles gated by DRBD quorum + daemon self-fence.

---

## What still needs doing (out of scope for v0.001)

- **ESP32 port**: core Rust proto crate is `no_std`; witness binary front-end
  needs an ESP-IDF/embassy wrapper and mbedTLS wiring instead of RustCrypto
  where hardware-accelerated.
- **Multi-path DRBD** (ring A + ring B): spec'd in early drafts, deferred —
  the node daemon already uses both rings for peer pings, but DRBD itself
  runs single-path v0.001.
- **Live VM guests on the replicated device**: the harness tests role
  transitions on an empty 64MB thin LV. Real VMs require the daemon to
  also issue `virsh start/shutdown` and update QEMU disk paths.
- **Multi-witness quorum** (3-witness, 5-witness): node daemon supports
  it logically (query N witnesses, count how many confirm peer dead);
  not yet wired into config or the harness.

---

*Pilot validated — next stop is ESP32.*
