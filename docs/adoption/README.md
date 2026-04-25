# Adopting the Echo Witness into existing clustering systems

The Echo protocol was designed so existing clustering systems can adopt it
with minimal friction. This folder explores how each would look.

**Pattern for all adoptions:**

1. Existing system elects a leader / negotiates roles using its own protocol.
2. Before taking a state-changing action, a node sends an Echo heartbeat
   carrying application-defined state in the 128-byte payload.
3. Witness records what each node last reported.
4. On split-brain suspicion, a node queries the witness for "what did my
   peer last say?" and decides safely.

The witness is **not** a replacement consensus participant. It's an
external memory with last-known state per node. Applications keep their
own protocol for consensus; they use the witness as durable diagnostic
of "who was where, when" and as a tiebreaker for lose-your-peer
scenarios.

## Systems covered

| System | 128 B payload would carry | Primary benefit |
|---|---|---|
| [DRBD](#drbd) | DRBD UUID + role per resource | Safe single-survivor promote after total outage |
| [Corosync qdevice](#corosync--pacemaker-qdevice) | qnetd-equivalent vote | Lightweight alternative to running qnetd |
| [Raft family](#raft-family-etcd-rqlite-consul-cockroachdb) | last committed index, term, role | External durable checkpoint in 2-node or split-AZ |
| [Galera / MariaDB](#galera--mariadb) | GTID, SST role | Arbitrator for 2-node Galera |
| [Patroni / PostgreSQL](#patroni--postgresql) | WAL LSN, replication slot | Lightweight alternative to etcd/Consul for small clusters |
| [Redis Sentinel](#redis-sentinel) | current master, failover epoch | Lightweight tiebreaker sentinel |
| [ZooKeeper](#zookeeper--kafka) | zxid, epoch | Tiebreaker for even-ensemble scenarios |
| [Ceph](#ceph) | MON epoch, CRUSH version | Stretched-cluster DC tiebreaker |
| [MinIO erasure clusters](#minio-erasure-clusters) | set epoch, zone health | Dual-site failover witness |
| [Nutanix Metro Availability](#nutanix-metro-availability) | DC primary flag, metadata epoch | Lightweight alternative to the Nutanix Witness VM |
| [VMware vSAN stretched clusters](#vmware-vsan-stretched-clusters) | site state | Would work; VMware probably won't adopt it |

---

## DRBD

**How DRBD already works:**
Two nodes, one DRBD resource per VM disk, synchronous replication over
protocol C. Roles (Primary/Secondary) are managed by whoever issues
`drbdadm primary/secondary`. DRBD has no built-in cluster membership
service; it relies on outside orchestration (Pacemaker, a custom
Python/shell daemon, manual admin).

**What Echo adds:**

- Node-level liveness: "is peer alive or dead?" with AEAD-authenticated
  answer and optional opaque peer state (up to 1152 bytes per node).
- 128-byte payload carries per-resource DRBD UUID + role bitmap.
- Advertise-verify-act before `drbdadm primary` → the witness has a
  durable record of "I intend to be Primary of bec-r0" before the
  promotion takes effect.

**Integration shapes:**

1. **Wrapper daemon (what Bedrock does):** one daemon per node,
   heartbeats on behalf of all local DRBD resources, 128 B payload
   encodes all of them.
2. **Native-ish integration:** a tiny helper hooked into DRBD's
   `notify-emergency-shutdown.sh` and similar handler scripts. On each
   resource state transition, the helper fires an Echo heartbeat. No
   daemon-proper; just event-driven.
3. **Per-resource daemon:** one daemon per DRBD resource, each with its
   own sender_id. Gives each resource independent Echo state. Overkill
   for small clusters, useful for multi-tenant hosts where resources
   belong to different admins.

**Suggested 128 B payload for DRBD:**

```
u64    current_log_tip_hash[4]   // 32 B; Bedrock cluster log tip
u64    log_length                //  8 B
u8     role                      //  1 B; 0=Secondary, 1=Primary, 2=mixed
u8     num_resources             //  1 B; up to N
u8     reserved[2]               //  2 B
struct { u64 uuid; u8 role; u8 disk_state; u8 pad[2]; } per_resource[7]
                                 // 84 B; 12 B × 7 resources
```

For > 7 resources, compact bitmap version omits UUIDs and just reports
role + disk_state per resource (1 B each → 128 resources in 128 B).

**Recovery:** covered in `docs/bedrock-cluster-log.md` §5.1.

---

## Corosync + Pacemaker (qdevice)

**How it already works:**
Corosync is the cluster membership layer for Pacemaker. For 2-node
clusters (or any even-node cluster), operators deploy **qdevice**, a
daemon on each cluster node that talks to an **qnetd** process running
on a separate (often third) machine. qnetd holds the decisive vote
when the two sides of the cluster can't reach each other.

**What Echo could replace:** `qnetd`. An Echo witness provides
essentially the same function (third-party tiebreaker), much smaller
(ESP32 vs. Linux VM running qnetd), with authenticated UDP instead of
qnetd's TCP/TLS.

**Integration shape:**

A `qdevice-echo` implementation on each Corosync node would behave like
qdevice: each time Corosync votequorum needs to know "is the third vote
reachable?", it calls into qdevice-echo, which does an Echo heartbeat
and interprets the response as "yes, quorum has 3 votes available" or
"no, down to 2 — see if we have majority with what we've got".

**Suggested 128 B payload:**

```
u64    corosync_ring_id          //  8 B; which ring we're in
u64    quorum_view_epoch         //  8 B
u32    active_votes_local        //  4 B
u32    expected_votes            //  4 B
u8     is_partitioned            //  1 B
u8     reserved[3]               //  3 B
u8     member_bitmap[100]        //100 B; bit i = member i is alive from our POV
```

**Benefit:** people running 2-node Pacemaker clusters today spin up a
third Linux VM just for qnetd. Replacing that with a $20 ESP32 that
serves dozens of small clusters simultaneously is a genuine operational
win.

**Watch out:** Corosync's own behaviour assumes qdevice ticks on the
order of every few seconds; Echo can match that easily at 3 s/heartbeat.

---

## Raft family (etcd, RQlite, Consul, CockroachDB, and Bedrock itself)

Raft is the motivating model for Bedrock's own clustering, so this
section goes deeper than the others.

**Important layer separation:** Echo's `sender_id` (1 byte) is the
witness-lookup identity, not Raft's internal `member_id`. Raft's
member_id (u64 in etcd, UUID in Consul, arbitrary in others) is
application-level and lives inside Echo's `own_payload`. The two
layers are independent — a Raft cluster can assign Echo sender_ids
1..N for its N members while keeping whatever internal member IDs
Raft itself uses.

### Echo's role for Raft: external checkpoint + liveness oracle

Echo is *not* a Raft voter. Raft's safety properties depend on
voters participating in log replication, which the witness doesn't.
Echo sits *outside* the voting ring, providing evidence that Raft
didn't have before.

### Use case 1 — Classic 3-site DR

```
    Site A                Site B              Site C (witness)
  ┌────────┐           ┌────────┐            ┌─────────┐
  │ R-node1│           │ R-node3│            │ Echo    │
  │ R-node2│───Raft────│ R-node4│─────UDP────│ witness │
  └────────┘           └────────┘            └─────────┘
        └─────UDP to Echo───┘                     │
        └─────UDP to Echo──────────────────────────┘
```

Every Raft node heartbeats Echo every 2s with its current
`{term, commit_index, last_log_index, state_hash}`. On site
partition, the surviving site's nodes query Echo for the isolated
site's last state:

- `peer.commit_index ≤ ours` → no committed-log-divergence possible,
  safe to continue serving.
- `peer.commit_index > ours` → peer had committed entries we don't
  have, UNSAFE, refuse writes, escalate.

This is a **crash-consistent external checkpoint** that Raft lacks
on its own. Raft traditionally has to assume-the-worst about
partitioned nodes; with Echo, it can verify.

### Use case 2 — Recovery after total cluster outage

Full multi-site power loss. Witness (battery-backed) retains state.
Raft nodes come back in staggered order. First node back:

1. Queries Echo for each known peer's last state.
2. For each peer, sees `term, commit_index, last_seen_ms, state_hash`.
3. Decision per Appendix A §A.5 of PROTOCOL.md:
   - Any peer with `commit_index > mine` → UNSAFE to lead; wait.
   - Peer with `commit_index == mine` and same `state_hash` → we're
     converged at peer's last checkpoint; safe to hold election once
     a second node joins.
   - All peers with `commit_index < mine` or no record → we're ahead
     or peer is permanently lost; proceed through normal recovery.

This works *because* Echo stored the full Raft state fingerprint in
`own_payload`. Pure liveness info wouldn't be enough.

### Use case 3 — Asymmetric partition detection

Raft's internal failure detector is peer-to-peer heartbeats. If
A↔B fails but A→C works fine, B times A out locally but A still
thinks it's alive. Raft can't disambiguate "A dead" from "A
partitioned from B only."

With Echo, B queries `STATUS_DETAIL(A.sender_id)` and sees A's
`last_seen_ms` from the witness's perspective:

- Small `last_seen_ms` → A is alive but can't reach B (network
  partition A↔B).
- Large `last_seen_ms` → A is either dead or partitioned from both
  B and the witness.

Enables smarter daemon-layer decisions: route requests via alternate
paths, proactively step down leadership, log meaningful alerts.

### Use case 4 — 2-node Raft + Echo-as-oracle (the surprising one)

Bare 2-node Raft deadlocks on leader election — neither has majority
for its own vote. Workarounds (learners, external lease managers,
static primary assignment) are all awkward.

Echo doesn't vote, so it doesn't directly solve this. But a daemon
layer can use Echo as an oracle:

```
On peer-unreachable timeout:
  query Echo for peer's STATUS_DETAIL(sender_id=peer)
  if peer.last_seen_ms < 10_000:      # peer alive, just partitioned from me
    do NOT promote; we're split-brain candidates
  else:                                # peer presumed dead
    advertise-verify-act via Echo (PROTOCOL.md Appendix A)
    if verification succeeds:
      promote self to leader, resume writes
```

This makes 2-node Raft-like clusters actually workable for small
deployments. The promotion is gated by Echo's durable evidence that
no split-brain is active.

### What Echo does NOT change in Raft

- Quorum math untouched. 3-node Raft still needs 2 of 3 for commits;
  5-node needs 3 of 5.
- Log replication untouched. Raft still does AppendEntries directly
  between nodes.
- Term numbering untouched. Nodes pick their own terms.
- Member management untouched. Raft conf changes happen via Raft's
  own ConfChange mechanism.

Echo adds *external evidence*; Raft's internal mechanics are
unchanged.

### Suggested payload schema for Raft-over-Echo

Fits in 128 B (leaves 1024 B of the 1152 B payload cap for future
extensions — signatures, Merkle proofs, peer attestations):

```
Offset  Size  Field                    Notes
──────────────────────────────────────────────────────────
0       8     raft_member_id           u64 (Raft's internal ID)
8       1     raft_role                0=follower, 1=candidate,
                                        2=leader, 3=learner
9       7     reserved                 align to u64 boundary
16      8     current_term             u64
24      8     voted_for_member         u64 (0 if none this term)
32      8     last_log_index           u64
40      8     last_log_term            u64
48      8     commit_index             u64
56      8     last_applied             u64
64      32    state_machine_root       [u8; 32] — Merkle/hash
96      32    log_tip_hash             [u8; 32] — hash of last N entries
──────────────────────────────────────────────────────────
Total: 128 bytes (expandable to 1152)
```

### Implementation sketch

1. **Raft node daemon** (one per Raft member):
   - Maintains its Raft member state locally (existing).
   - Runs an Echo node client with assigned sender_id (1..N within
     cluster).
   - Bootstraps the Echo session at startup.
   - Every 2 s: heartbeats Echo with `own_payload = current Raft
     state snapshot`. Uses STATUS_DETAIL to query a specific peer
     when needed (failure detection, recovery decision).

2. **Raft cluster config** adds Echo fields:
   ```yaml
   raft:
     member_id: 0xf7c3a82e6414e63a
     peers: [...]
   echo:
     sender_id: 3                         # 1..N, unique in this cluster
     cluster_key: <32B from provisioning>
     witness_pubkeys:                     # list for HA
       - { addr: witness-a.example:12321, pubkey: <32B> }
       - { addr: witness-b.example:12321, pubkey: <32B> }
       - { addr: witness-c.example:12321, pubkey: <32B> }
   ```

3. **Recovery decision module** consults Echo before any forced
   reconfiguration or 2-node promotion. Safety comes from the
   advertise-verify-act pattern.

### Bedrock's own clustering

Bedrock's planned distributed behavior is Raft-inspired. Echo is
Bedrock's witness. The 4 use cases above apply directly to Bedrock.
See `docs/bedrock-cluster-log.md` for the hash-chained log design
and Appendix A of PROTOCOL.md for the safety pattern.

---

## Galera / MariaDB

**How it already works:** Galera is a synchronous replication cluster
for MariaDB/MySQL. Needs odd-node quorum (3+). 2-node setups are
brittle — if they can't reach each other, both stop accepting writes.
The MariaDB ecosystem provides `garbd` (Galera Arbitrator Daemon) — a
lightweight voter that doesn't replicate data but participates in
quorum calculations.

**What Echo could replace:** `garbd`. Very small footprint for a
tiebreaker role.

**Integration:** a node-side shim listens to Galera status changes
(via SHOW STATUS or wsrep_notify_cmd hook) and heartbeats the witness.

**Suggested 128 B payload:**

```
u8     wsrep_cluster_size        //  1 B; expected size
u8     wsrep_local_state         //  1 B; JOINED/SYNCED/...
u8     local_weight              //  1 B; vote weight
u8     reserved[5]               //  5 B
i64    seqno                     //  8 B; wsrep_last_committed
u8     gtid_uuid[16]             // 16 B; UUID of current Galera state
u8     flow_control_paused       //  1 B
u8     reserved2[95]             // 95 B future use
```

---

## Patroni / PostgreSQL

**How it already works:** Patroni is a PostgreSQL HA tool using
etcd/Consul/ZooKeeper for distributed state. Single leader; followers
stream WAL. Failover is managed by Patroni reading DCS (distributed
configuration store) state. DCS is the single source of truth.

**What Echo could do:** replace small-scale DCS (etcd cluster) for
tiny 2-node Patroni setups where spinning up etcd is overkill. The
witness holds the same cluster-view metadata that Patroni reads from
etcd.

**Integration:** a Patroni extension that uses Echo as DCS. Callbacks
`read_dcs`, `write_dcs`, `acquire_lock` map onto Echo heartbeat-query
cycles. Limited to small-scale because Echo's witness has a single
128 B opaque payload per node — no room for per-database detail.

**Suggested 128 B payload:**

```
u8     role                      //  1 B; 0=replica, 1=primary
u8     in_recovery               //  1 B
u8     reserved[6]               //  6 B
u64    wal_lsn                   //  8 B; current WAL write location
u64    wal_lsn_replay            //  8 B; replica replay location
u8     lock_holder[8]            //  8 B; sender_id of current lock owner
u64    lock_epoch                //  8 B
u8     cluster_id[16]            // 16 B; Patroni cluster identifier hash
u8     reserved2[72]             // 72 B future
```

**Caveat:** not a full DCS replacement — can't handle multi-leader
configurations, complex membership changes, etc. Fine for 2-node
primary/replica.

---

## Redis Sentinel

**How it already works:** Redis Sentinel is a group of sentinel
processes that monitor Redis master/replica pairs and handle failover.
Needs quorum of sentinels (typically 3+) to agree a master is down.

**What Echo could be:** a "lightweight sentinel" that participates in
the quorum count for small 2-sentinel deployments. Or: if you only
want 1 real Sentinel plus a witness, Echo provides the tiebreaker.

**Suggested 128 B payload:**

```
u8     current_role              //  1 B; 0=observer, 1=sentinel
u8     reserved[3]               //  3 B
u32    failover_epoch            //  4 B
u8     current_master_id[16]     // 16 B; hash of master name
u8     current_master_ip[4]      //  4 B
u16    current_master_port       //  2 B
u8     reserved2[2]
u64    sentinel_view_timestamp   //  8 B
u8     reserved3[88]             // 88 B
```

---

## ZooKeeper / Kafka

**How it already works:** ZooKeeper needs an odd-sized ensemble (3, 5, 7).
Kafka (pre-KRaft) depends on ZK. KRaft itself is Raft under the hood
(see above).

**What Echo could do:** tiebreaker for odd ensemble size (4) — treat
the witness as an "honorary observer" that reports the last seen zxid.
Booting after outage, the observing ensemble members can reconstruct
which peer had the highest zxid (most recent commits) and start
election from that state.

Same limitation as Raft: not a voter, a checkpoint.

**Suggested 128 B payload:**

```
u8     role                      //  1 B; 0=follower, 1=leader, 2=observer
u8     reserved[3]
u64    zxid                      //  8 B; zookeeper transaction id
u64    leader_epoch              //  8 B
u8     leader_id[8]              //  8 B
u8     ensemble_version          //  1 B
u8     reserved2[99]
```

---

## Ceph

**How it already works:** Ceph monitors (MONs) run Paxos for cluster
map consensus. Production needs 3+ MONs. OSDs (storage daemons) query
MONs for cluster state. Stretched (dual-DC) clusters typically use
site weighting to handle DC-level failure but can still deadlock in
specific topologies.

**What Echo could do:**

The Ceph MON role cannot be replaced by Echo — MONs run full Paxos and
hold persistent cluster-map state. Echo's witness is too simple for
that.

**But** for **client-side DC failover decisions** in stretched clusters,
Echo could be a lightweight oracle: which DC currently owns a given
"pool" or "crush rule"? The MONs within each DC can heartbeat the
witness; a client library reads the witness to decide which DC's
MONs to prefer.

Alternatively: a custom "which-DC-is-live" witness where each DC's
gateway heartbeats on behalf of the whole DC. Not vanilla Ceph
functionality — requires a wrapper layer.

**Suggested 128 B payload (per-DC gateway):**

```
u8     dc_id[8]                  //  8 B; DC identifier
u8     dc_state                  //  1 B; 0=dead, 1=degraded, 2=healthy
u8     num_alive_mons            //  1 B
u8     num_alive_osds            //  1 B
u8     reserved[5]
u64    osdmap_epoch              //  8 B
u8     primary_pool_mask[16]     // 16 B; which pools this DC is primary for
u8     reserved2[88]
```

---

## MinIO erasure clusters

**How it already works:** MinIO distributed mode shards objects across
nodes with erasure coding. Failover of metadata is handled via quorum
of nodes holding each object's metadata.

**What Echo could do:** similar to Ceph — not a MinIO metadata peer,
but a dual-site failover witness for active/passive site configurations.

**Suggested 128 B payload:** similar to Ceph's per-DC gateway shape.

---

## Nutanix Metro Availability

**How it already works:** Nutanix Metro Availability uses a "Witness VM"
in a third location to break ties during DC-level partition events.
The Witness VM is a full Linux VM with Nutanix-specific code running
permanently — not a tiny device.

**What Echo could do:** be the witness. A $20 ESP32 on the customer's
third-site network (office router co-location? rented VPS?) does the
job that a full Witness VM does today. Nutanix could ship an Echo-
compatible firmware image + a small daemon on their CVMs. Substantial
cost and complexity reduction for customers.

**Nutanix's likely reaction:** adopting an outside protocol would require
engineering work and reduce their control. Probably unlikely for the
enterprise product. An open-source contribution that works *alongside*
their Witness VM (failover to Echo if the Witness VM is down, or vice
versa) might be more palatable.

**Suggested 128 B payload:**

```
u8     cluster_role              //  1 B; 0=secondary_site, 1=primary_site
u8     replication_state         //  1 B; synced, lagging, broken
u8     reserved[6]
u64    metadata_epoch            //  8 B
u8     cluster_id_hash[16]       // 16 B
u32    num_pds_active            //  4 B; protection domains
u8     reserved2[92]
```

---

## VMware vSAN stretched clusters

**How it already works:** vSAN stretched clusters use a "Witness
Host" — a full ESXi instance running a minimal vSAN witness. Its role:
per-object quorum for 2-site configurations, DC-level failover
decisions.

**What Echo could do:** the DC-level failover use (which site owns a
VM right now) could be served by Echo. The per-object quorum use
cannot — Echo is not designed to hold per-vSAN-object metadata.

**VMware's likely reaction:** after the Broadcom pricing saga, vSAN is
losing customers fast. VMware is unlikely to adopt a competing
protocol from a small open-source project. A shim that implements
"Echo witness ↔ vSAN witness protocol translator" could let refugees
bring their stretched clusters to a simpler tiebreaker platform while
migrating off vSAN entirely.

VMware will love this approximately as much as they love Bedrock — but
good engineers working inside Broadcom may quietly applaud.

---

## Summary

**Systems where Echo could directly replace an existing component:**
- Corosync qnetd
- Galera `garbd`
- Small-scale Patroni DCS (alternative to etcd)
- Nutanix Witness VM (needs cooperation from Nutanix)

**Systems where Echo could be a useful adjunct tiebreaker:**
- DRBD (primary Bedrock use case; stand-alone via a small wrapper)
- Raft family — external checkpoint, not a voter
- Ceph / MinIO — DC-level failover for stretched clusters
- ZooKeeper — checkpoint for even ensembles
- Redis Sentinel — lightweight sentinel member

**Systems where Echo is theoretically possible but politically unlikely:**
- VMware vSAN — could work; Broadcom-era vSAN won't adopt it
- Nutanix — could work; proprietary pride may block it

**Systems Echo cannot replace:**
- Raft/Paxos voter roles — witness doesn't participate in log
  replication, doesn't store per-transaction state
- Ceph MONs — too much per-object state
- Anything requiring persistent multi-megabyte state with writes on
  every operation

The right framing: **Echo is a node-level liveness oracle with an
opaque 128-byte per-node state channel.** Any clustering system that can
map its failover decision onto "what did my peer last say?" can use it.
