# Bedrock Cluster Log — Design Draft

**Status:** Design draft, not yet implemented. Not part of the Echo protocol
spec (and must never become part of it — see [§ Separation of concerns](#separation-of-concerns)).

**Scope:** this document describes a *Bedrock clustering layer* feature —
how Bedrock nodes will record and agree on cluster-wide state transitions
(DRBD promotions, VM migrations, admin actions, failover decisions).
The Echo witness is one small building block this feature uses; the design
below is the envelope around that building block.

---

## 1. What problem this solves

Today, after a cluster event that touches persistent state (a DRBD
promotion, a VM migration, a forced failover), two sources of truth exist:

1. **Local state on each node** — DRBD metadata on disk, libvirt XML, etc.
2. **Operator memory** — which they will lose.

When a node crashes and comes back, the ONLY thing it can use to answer
"was I the correct Primary at the moment of the crash?" is a combination of:

- Its own DRBD UUID (tells it where it was at last write)
- What the witness last heard from the peer
- What the operator said in the postmortem

This is enough for the simple case (both nodes synced at crash, one
survivor). It falls short for anything more complex:

- "Node A migrated a VM to node B at T=100, then B crashed at T=110. A
  boots alone at T=200. A has no record of the migration. A might try
  to re-promote a resource that B was rightfully serving at the moment
  of crash."
- "A fenced B at T=50 (admin override). B booted at T=200 unaware.
  Without a shared log, B thinks it was still Primary."
- "Someone pressed the wrong button at T=30 and only one node's log
  recorded it. Reconstruction is impossible."

The **Bedrock Cluster Log** is a hash-chained, append-only journal of
cluster state transitions. Its chain tip is communicated via the Echo
witness's 128-byte payload. Both nodes can verify they have the same
history by comparing tip hashes; a survivor can verify peer's
last-known-tip matches its own; reconstruction is possible.

---

## 2. High-level shape

```
┌─────────────────────────────────────────────────────────────────┐
│                      Bedrock Cluster Log                         │
│                   (Bedrock node daemon layer)                    │
│                                                                  │
│   local log:                                                     │
│   ─────────                                                      │
│   ├── entry 0:  BOOTSTRAP {cluster_id, initial_members}          │
│   ├── entry 1:  PROMOTE {res=bec-r0, actor=nodeA, uuid=xxx}      │
│   ├── entry 2:  MIGRATE {vm=vm-web, from=A, to=B}                │
│   ├── ...                                                        │
│   └── entry N:  tip_hash = H(entry N)                            │
│                                                                  │
│   each entry = { prev_hash, timestamp, actor, action, payload,   │
│                   signature_from_actor }                         │
│                                                                  │
│   tip_hash → packed into witness payload                         │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                      Echo Witness (protocol)                     │
│                                                                  │
│   Per-node 128-byte payload (opaque to witness, defined here):   │
│                                                                  │
│     log_tip_hash:    32 B   (SHA-256 of my latest log entry)     │
│     log_length:       8 B   (monotonic count; catches lag)       │
│     node_flags:       4 B   (role bitmap, healthy/degraded, etc.)│
│     per-resource-status:  up to 84 B remaining                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

Each node maintains the log locally. Nodes sync entries to each other
directly when connected. On any state-changing action, the acting node
appends an entry, advances its tip, announces the new tip to the witness
via heartbeat, and verifies (see the advertise-verify-act pattern below)
before committing the real action.

---

## 3. Log entry format (proposed)

```
Entry {
    prev_hash:   [u8; 32]     # SHA-256 of the prior entry's full record
    index:       u64           # 0-based sequence number; strict +1 per entry
    timestamp:   i64           # ms since Unix epoch (advisory, not trusted)
    actor:       [u8; 8]       # sender_id of the node that appended this
    action:      u8            # kind — see table below
    payload_len: u16           # length of action-specific payload
    payload:     [u8; N]       # action-specific, ≤ 1024 B
    actor_sig:   [u8; 64]      # Ed25519 signature over the entry
}
```

Full-entry hash = SHA-256(prev_hash || index || timestamp || actor ||
action || payload_len || payload || actor_sig).

`prev_hash` of entry 0 is all-zero. This creates a tamper-evident chain.

**Action types (proposed):**

| Code | Name | When |
|---|---|---|
| 0x01 | `BOOTSTRAP` | Cluster creation; first entry |
| 0x02 | `JOIN_NODE` | New node added to cluster |
| 0x03 | `REMOVE_NODE` | Node decommissioned |
| 0x10 | `PROMOTE_RESOURCE` | DRBD resource promoted to Primary |
| 0x11 | `DEMOTE_RESOURCE` | DRBD resource demoted |
| 0x12 | `START_VM` | VM started on a node |
| 0x13 | `STOP_VM` | VM stopped |
| 0x14 | `MIGRATE_VM` | VM live-migrated |
| 0x20 | `FENCE_NODE` | Admin or auto-fence of a node |
| 0x21 | `CLUSTER_FREEZE` | Administrative pause; block state changes |
| 0x22 | `CLUSTER_THAW` | Resume from freeze |
| 0xFE | `HEARTBEAT_MARK` | Periodic checkpoint (see §6) |
| 0xFF | `COMMENT` | Human note, no semantic effect |

---

## 4. Writing an entry — the advertise-verify-act pattern

For actions with persistent effect (promotions, migrations, fences):

```
1.  Append entry to LOCAL log, compute new tip_hash.
2.  Announce intent via Echo heartbeat:
      payload = { log_tip_hash = new_tip, log_length = N+1, status=pending }
3.  Query witness: STATUS_DETAIL target=my_sender_id.
4.  If witness's recorded payload matches what I just announced:
       → the new tip is durably recorded externally
       → SAFE to perform the real action (drbdadm primary, virsh start, …)
    Else:
       → retry from step 2, or abort and undo the local append
5.  Perform the action.
6.  Announce completion:
      payload = { log_tip_hash = new_tip, log_length = N+1, status=committed }
```

If the node crashes between step 4 and step 5, recovery finds "intent
announced but no completion" → re-drives the action (idempotent where
possible) or flags for operator review.

If the witness goes unreachable between steps 2 and 3, step 4 fails
(no verification) → abort. Local log append is rolled back. No
divergence.

**For non-persistent actions** (startup banners, monitoring polls, routine
heartbeats) no log entry is made; just the regular heartbeat.

---

## 5. Recovery scenarios

### 5.1 Single-survivor recovery (the canonical case)

```
Node A (survivor)                     Witness
──────────────────────────────────────────────
boot, read local log:
  my_tip = H_A (from local disk)
bootstrap to witness
query STATUS_DETAIL target=node-B  ────►
                                        reply with B's last payload:
                                          { log_tip=H_B, log_length=N_B, status=committed }
                                          last_seen_seconds=86400
                                          (24h ago)
compare:
  If H_A == H_B and N_A == N_B:
      → we were synced at B's last checkpoint
      → no writes happened between (otherwise tips would differ)
      → SAFE to operate unilaterally
      → append FENCE_NODE entry for B
      → advertise-verify-act the promotion
      → proceed
  If N_A < N_B:
      → B had newer entries I never saw
      → UNSAFE; refuse; operator required
  If N_A > N_B:
      → I have newer entries B never saw
      → I was authoritative; continue with my log
```

### 5.2 Both nodes boot simultaneously

Both nodes heartbeat with their local tip + length. Both query for peer.

- If peer's last_seen_seconds is recent (< 30 s) → peer is alive and
  booting too. Neither unilaterally promotes. Normal cluster convergence
  happens via direct peer-to-peer log sync.
- If peer's tip/length disagree → log divergence; admin required.

### 5.3 Witness was also rebooted

No peer record available. Neither node can make a safe unilateral
decision. Both remain Secondary (or remain in their current role, if a
Primary came up alone). Operator intervention required.

Mitigation: battery-backed witness (72+ hour). If the witness died,
that's a deployment failure and human intervention is the correct response.

### 5.4 Log divergence (both nodes wrote independently)

Shouldn't happen under advertise-verify-act; if it does (bug, manual
drbdadm without the daemon, etc.), the cluster enters FROZEN state. Both
nodes keep heartbeating with their divergent tips. Dashboard shows a
prominent divergence alert. Admin chooses which log to canonicalise.

---

## 6. Retention, pruning, and snapshots

Keeping the log forever is cheap (an entry is ~150 B + payload; 10 entries
per day × 10 years = 550 KB). But:

- Walking the chain on every boot is slow if it's long.
- Some entries reference transient state (a VM that was later removed).

**Proposed:** a `HEARTBEAT_MARK` entry every N hours (e.g., every 24 h)
that carries a **snapshot** of the current cluster state. At any
`HEARTBEAT_MARK` entry, the log before that point can be archived but not
discarded (the hash chain stays intact). Normal boots only read back to
the last `HEARTBEAT_MARK`.

---

## 7. Synchronisation between nodes

When both nodes are up and can talk directly:

- **Append pattern:** actor appends locally, peer receives a push (TCP
  connection on a chosen port, TLS with the cluster_key as PSK) with the
  new entry, peer verifies hash chain + signature, appends to its own log.
- **Reconnect pattern:** after a network partition, nodes compare tips.
  Whichever tip is "ahead" (longer, consistent chain) is authoritative
  for entries the other missed. Other side pulls range [N_short, N_long].

This is similar to Raft log replication but simpler (2 nodes, no voting).
The witness is *not* part of the normal sync — it only holds the tip
hash for the disaster-recovery case.

---

## 8. Security model

- **Signatures:** each entry signed by its actor with an Ed25519 key.
  (This is the first place Bedrock would use Ed25519 — not the Echo
  protocol itself.) Actor's Ed25519 pubkey is recorded in the BOOTSTRAP
  or JOIN_NODE entry, so any replay is verifiable.
- **Transport:** direct node↔node sync is over TLS (cluster_key as PSK,
  or separate mutual-TLS certs).
- **Tampering resistance:** altering any past entry changes its hash,
  which breaks the chain for every subsequent entry. A tampered log
  would mismatch both peer AND witness tip.
- **Witness trust:** the witness holds only the tip hash, not entry
  contents. It cannot forge log history, only misreport the tip. HMAC
  on witness replies prevents remote forgery.

---

## 9. Open questions

- **Entry payload schemas.** Each action type needs a defined payload.
  That's deferable — BOOTSTRAP/PROMOTE/DEMOTE are enough.
- **Multi-witness support.** If 3 witnesses vote, do they need to agree
  on the tip hash? (Yes, probably, by the querying node.)
- **Clock skew for `timestamp`.** Not trusted for ordering (index is);
  advisory only.
- **Log compaction.** After N `HEARTBEAT_MARK`s, snapshot + discard old
  log file, but keep the chain hash linkage.
- **Subscribers.** Should external systems (monitoring, backup) be able
  to subscribe to log entries? Probably yes; easy enough via the same
  cluster-key TLS channel.

---

## 10. Separation of concerns

The Echo protocol spec **must not** include:

- The log entry format
- The action types
- Any of this design

Reasons:

1. The Echo witness should remain stateless-of-application-semantics
   forever. It stores opaque 128-byte payloads. Any application
   (DRBD, Corosync, Ceph, ZK, Bedrock) defines its own schema inside that
   payload.
2. If the Bedrock log format needs to evolve, it should never require a
   witness firmware update in the field.
3. A witness serving 32 different clusters of different applications
   should not need to know that cluster 17 is Bedrock-with-cluster-log
   and cluster 23 is Corosync-with-qdevice-flavour. It's all opaque
   bytes.

Therefore this design lives under `docs/` and is a Bedrock-daemon
concern, not a protocol concern.

---

## 11. Minimum viable log (what to build first)

For v0.1 of the Bedrock node daemon:

- File-backed append-only log at `/var/lib/bedrock/cluster.log`.
- One action type: `PROMOTE_RESOURCE` (the failover case).
- SHA-256 chain, no signatures yet (add Ed25519 in v0.2).
- On daemon start: read log, compute tip, heartbeat witness with tip.
- On promote: append entry, advertise-verify-act, then `drbdadm primary`.
- On peer reconnect: exchange tips; if divergent, freeze.

Everything else (MIGRATE_VM, FENCE_NODE, HEARTBEAT_MARK snapshots,
compaction, subscribers) is follow-up work.
