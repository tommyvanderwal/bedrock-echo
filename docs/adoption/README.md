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

- Node-level liveness: "is peer alive or dead?" with HMAC-authenticated
  answer and optional 128-byte peer state.
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

## Raft family (etcd, RQlite, Consul, CockroachDB)

**How it already works:** Raft requires ≥ 3 voting members for
fault-tolerance. Odd counts only (to avoid split votes). With 3 members,
1 can fail; with 5, 2 can fail. In 2-DC deployments, a 5-node cluster
typically runs 3 in DC-A and 2 in DC-B; losing DC-A → minority → stall.

**What Echo could be used for:**

- **Lightweight "non-voting follower" role**: not a Raft voter, but a
  durable external checkpoint. Periodically, the current leader sends
  a heartbeat containing `{term, last_applied_index, leader_id}`.
- **Recovery after total cluster outage**: the first node to boot can
  query the witness for each peer's last known state. Among the peers,
  the one with the highest `last_applied_index` has the most
  up-to-date log. That node should be the leader candidate in the
  recovering quorum.

**What Echo would NOT do:** vote in Raft elections. Raft requires
voters to actually participate in log replication, which our witness
doesn't. Attempting to add the witness as a Raft voter would break
Raft's safety properties.

**Suggested 128 B payload:**

```
u8     raft_role                 //  1 B; 0=follower, 1=candidate, 2=leader
u8     reserved[3]               //  3 B
u64    current_term              //  8 B
u64    last_log_index            //  8 B
u64    last_applied_index        //  8 B
u8     voted_for_node_id[8]      //  8 B
u8     leader_id[8]              //  8 B (zero if unknown)
u8     reserved2[8]              //  8 B
u8     cluster_id_hash[32]       // 32 B; SHA-256 of membership config
u8     reserved3[44]             // 44 B padding
```

**Benefit for 2-DC scenarios:** split DCs at 3+2; DC-B survivor queries
the Echo witness in a third location, sees "DC-A last reported term=5
index=1000, now silent for 2 minutes", and can start a forced
reconfiguration safely knowing DC-A was not ahead.

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
