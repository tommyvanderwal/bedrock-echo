# Bedrock Echo — design notes (non-normative)

Living document. Captures design rationale, non-issues we explored and dismissed,
open questions, and guidance that belongs near the spec but not *in* it.
`PROTOCOL.md` is the normative contract; this file is the reasoning.

---

## 1. Things that look like gaps but aren't

### 1.1 Cluster-key "rotation" is not a protocol gap

On first read, it looks like Echo is missing a way to rotate a compromised
cluster key. This was flagged during review as a real issue. It isn't,
and the final design (with sender_id collision resolution — §2.1 of this
doc) makes the rotation path even smoother than the original design did.

**Under collision-resolution semantics:** bootstrap of an existing
sender_id with a *different* cluster_key creates a *new* node entry
alongside the old one (both share the sender_id, distinguished by
cluster_key). The old cluster continues operating under its old key
until its nodes stop heartbeating; new cluster operates under the new
key. No coordination with the witness required — the two coexist.

Migration path:
1. Operators coordinate a new cluster_key K2 out-of-band.
2. Nodes bootstrap into the new cluster (same sender_ids, new key).
   Witness now has two entries per node (one for K1, one for K2).
3. Any cluster-layer failover decisions pause while both exist.
4. Once all nodes have migrated, old entries age out naturally
   (72 h at normal fill per §10).

**"Is there a cluster protocol that does in-place secret rotation well?"**
No. WireGuard punts (remove-and-re-add peer). Corosync's `cryptokey` needs
rolling restart. etcd/Consul rotate TLS certs, not the cluster secret.
ZooKeeper's superdigest rotation is famously clunky. Echo's path is
better than any of them because the witness carries no migration-worthy
state (the key IS the identity) and old + new clusters coexist
transparently during the transition window. Not a gap.

### 1.2 No "sequence-rejected, please re-bootstrap" feedback

A node whose heartbeats are being silently dropped (sequence stuck below
witness's `last_rx`) gets no diagnostic signal — only a timeout, identical
to "witness unreachable." Reviewing this, we considered adding a diagnostic
reply type.

**Why silence is correct:** any information emitted by the witness is an
information-leak channel across clusters sharing one witness. "Your
sequence is behind" tells an attacker that a node with a given sender_id
was recently active on this witness. The witness serves potentially many
clusters; privacy between them is load-bearing. Troubleshooting happens at
the node side (node has its own logs) or on the witness console (admin
with local access).

Not a gap — silence is a feature.

### 1.3 Multi-witness HA is not a protocol concern

The protocol is point-to-point. A node daemon can maintain N independent
relationships with N witnesses, each with its own BOOTSTRAP, cluster_key,
sequence window, and HMAC context. The daemon applies whatever quorum rule
it wants across those N views ("2-of-3 witnesses agree peer is dead" etc.).

Nothing in the wire format prevents this. It's a deployment/daemon concern,
not a protocol concern. The "single witness" appearance of `PROTOCOL.md`
reflects the pilot's topology, not a protocol constraint.

Guidance: production deployments wanting HA should run N = 3 or 5 witnesses
on separate failure domains and have node daemons require a majority.

---

## 2. Open design questions (pre-freeze)

### 2.1 Node payload size: **0..36 blocks of 32 B (= 0..1152 B)**

**Decided:** `own_payload`, `peer_payload`, and `init_payload` are
variable-length, encoded on the wire as a **block count (u8)** followed
by `block_count × 32` bytes. Every conformant implementation MUST
support 0..36 blocks (0..1152 B). No optional tiers.

**Why block-granular, not byte-granular:**
- Wire format matches witness storage granularity exactly. The ESP32
  block allocator uses 32-B blocks; receiving a packet that declares
  N blocks maps directly to allocating N blocks from the pool. No
  byte-to-block arithmetic, no partial-block accounting.
- Alignment: in HEARTBEAT, the payload section starts at offset 14
  (after the header) with `query_target_id(1) + own_payload_blocks(1)`
  placing `own_payload` at offset 16 — **16-byte aligned start, every
  32-byte block thereafter is 16-byte aligned**. Matters for Cortex-M
  `ldmia`/`stmia`, x86 SIMD, and any hardware that prefers aligned
  loads. Free win.
- App-side cost is bounded: if an app has 50 B of state, it uses 2
  blocks (64 B) and pads 14 B with whatever it wants (zeros, magic,
  schema version). Worst-case padding waste = 31 B per packet.

**Why 1152 B (= 36 × 32 = 1024 + 128):**
- Gives apps a clean conceptual split: 1024 B "data" + 128 B "app
  metadata" (signature, schema version, app-level checksum, …). The
  witness treats it all as opaque.
- Fits the 1400 B MTU cap with protocol overhead and headroom:
  - HEARTBEAT max = 14 + 2 + 1152 + 32 = **1200 B** (200 B slack)
  - STATUS_DETAIL max ≈ 14 + 22 + 1152 + 32 = **1220 B** (180 B slack)
  - BOOTSTRAP max ≈ 14 + 32 + 32 + 1152 + 16 = **1246 B** (154 B slack)
  - STATUS_LIST unchanged (16-B entries, 64 entries → ~1108 B).
- 1152 / 32 = 36, and 36 fits cleanly in a u8 block-count field.

**MTU cap stays 1400 B.** No IP fragmentation. 1 packet = 1 message.

### 2.2 ESP32 block-allocator design

Node storage moves from fixed-inline (128 B per slot × 256 slots = 32 KB
fixed .bss) to a **fixed-size pool of 32 B blocks**, with each node
entry storing `(first_block, n_blocks, payload_len)`.

**No bitmap needed.** The node table itself is the allocation map.
To find a free run of N blocks: walk the node table, build a sorted
list of used `(start, end)` intervals, scan gaps. O(M log M) per
allocation where M = nodes in use (≤ 256), so ~2 k ops — negligible.

Rationale: single source of truth (the node table) is more elegant than
keeping a parallel bitmap in sync, and the bytes saved (~256 B) are
trivial. The cost is allocation-time CPU, which is cheap.

**Defragmentation: always pack toward one fixed end.**

Compaction direction is fixed — let's say LOW. After defrag, all
allocated blocks live in `[0, cursor)` and free space is one
contiguous run in `[cursor, TOTAL_BLOCKS)`. New allocations always
come from the high free zone. Next defrag cycle goes the same
direction. No alternation, no reserved scratch zone.

```c
qsort(node_table, by_start_block);
uint16_t cursor = 0;
for (each used node N in sorted order) {
    if (N.first_block > cursor) {
        memmove(pool + cursor*32, pool + N.first_block*32, N.n_blocks*32);
        N.first_block = cursor;
    }
    cursor += N.n_blocks;
}
// blocks [cursor, TOTAL_BLOCKS) are now all free.
```

`memmove` handles overlap correctly (always shifts down into a
known-free region behind the cursor). Worst-case defrag of a packed
73 KB pool is one big memmove ≈ 700 μs on ESP32 — acceptable hiccup.
Defrag triggered only on allocation failure with sufficient total
free blocks (i.e., genuinely fragmented).

**Sizing for ESP32-POE-ISO** (180 KB DRAM total, ESP-IDF baseline
~12 KB, target ≥50 KB heap headroom).

**Decided profile for the ESP32 big build:**

| Item | Size |
|---|---:|
| Node table (512 × ~56 B) | ~29 KB |
| Cluster table (256 × 48 B) | ~12 KB |
| Rate-limit table (192 × 28 B) | ~5 KB |
| Block pool (1152 blocks × 32 B) | ~36 KB |
| ESP-IDF baseline | ~12 KB |
| **Total .bss** | **~94 KB** |
| **Heap remaining** | **~86 KB** |

Capacity:
- Up to **512 tracked nodes** across **256 clusters**.
- Pool supports simultaneously: 32 fully-fat (1152 B) nodes, or 1152
  minimum-single-block (32 B) nodes, or any mix in between.
- Rationale: typical deployments have many nodes with small payloads
  (DRBD UUIDs are 32-64 B; Raft tips 48 B). Fat capacity reserved
  for the occasional signature-bearing attestation. The metadata
  table dominates sizing, the pool stays lean.

**Growth-into-full-pool handling:**

Node currently using N blocks sends a larger heartbeat needing M > N
blocks. Witness allocates new (first_block, n_blocks) for the larger
payload first, then frees the old blocks on success:

```
new_first = alloc_blocks(M)
if new_first < 0:
    if defrag_could_help(M):  // total free blocks ≥ M but fragmented
        defrag()
        new_first = alloc_blocks(M)
if new_first < 0:
    silent drop — node entry keeps its old smaller payload unchanged
else:
    copy pkt_payload → pool[new_first..new_first+M]
    free_blocks(old_first, N)
    update node entry to (new_first, M)
```

Silent drop is the universal failure response. Consequences compose
cleanly:
- Pool at 80% fill → age-out tier 4 h kicks in (§10). Stale entries
  reclaim faster.
- Pool at 90% → age-out 5 min.
- Node retrying fat payload into saturated pool → its own silent-drops
  time it out at whatever tier is active → its entry (and its blocks)
  get freed → retry succeeds.
- Genuinely over capacity (pool full of recent active entries all
  wanting to grow) → raise pool size or accept update drops until
  a node legitimately dies. Deployment-sizing problem, not a
  protocol-semantics problem.

**Age-out tier policy (§10) applies to block-pool fill** as it does to
slot-table fill: at 80% blocks used, reclaim at 4 h; at 90%, reclaim
at 5 min. Pool pressure handled by the same mechanism that handles
slot-table pressure.

**Implementation effort:**
- Rust witness: trivial — `Vec<u8>` or `heapless::Vec<u8, 1152>`. Linux
  witness uses heap; no allocator needed.
- Python: trivial — `bytes`.
- C witness on ESP32: ~150 lines of C for the bitmap-free block
  allocator + defrag. One-time cost, well-understood pattern.

**Consequence for the spec:** `own_payload ≤ 128` (§4.1), `peer_payload
≤ 128` (§4.3), `init_payload ≤ 96` (§4.5) all change to ≤ 1152.
Total-size math in §3 message table updates. Test vectors gain a
fat-payload case to prove conformance.

### 2.2 Unit consistency: seconds → ms everywhere

Current spec has `last_seen_seconds` (u32 seconds) in STATUS replies,
while every other duration is in ms. Inconsistent for no reason — 72 h
age-out is 259 200 seconds = 259 200 000 ms, fits easily in u32 ms
(u32 max = ~49 days).

**Action when unfrozen:** rename `last_seen_seconds` → `last_seen_ms`,
u32 ms. Same field size. 1000× resolution improvement. Regenerate the
three affected test vectors.

---

## 3. Anti-replay and time — the sharp version

**This section captures a design idea that trades some header complexity
for qualitatively stronger anti-replay semantics. Not yet adopted.**

### 3.1 What the current spec guarantees

`sequence` (u64, per sender) is the sole anti-replay primitive. Witness
tracks `last_rx_sequence[sender_id]`; packet must be strictly greater.
Recommended derivation: `next_seq = max(wall_ms_since_epoch, last_sent + 1)`.

**Strong case (steady state within one continuous session):** sequence
advances past every old value; replay drops.

**Weak edges (two reset points):**
- **Node restart:** If node has wall-clock (our target deployments do),
  new sequences are wall_ms-derived, necessarily > every captured old
  sequence — self-heals. If node is RTC-less and loses state, sequence
  resets to 1; captured packets with seq > 1 can replay until the node
  re-BOOTSTRAPs.
- **Witness restart:** Witness loses all state. Next BOOTSTRAP resets
  `last_rx = 0`. Attacker can replay captured packets in the window
  between BOOTSTRAP_ACK and the next real heartbeat (~3 s). Replay
  momentarily shows stale `own_payload` until real heartbeat overwrites.

The Appendix A advertise-verify-act pattern mostly defends operationally
(decision rules account for `last_seen_seconds` being small, Appendix A
§A.5 "hold if peer is alive and recent"). Residual exposure is narrow.

### 3.2 Proposed alternative: unified wall-clock-ms timing

Design: make `timestamp_ms` the anti-replay marker, drop `sequence` as a
separate field, and have the witness synthesize "cluster-frame wall time"
in its replies without needing its own RTC.

**Wire-level change:**
- `timestamp_ms` (i64) becomes **mandatory non-zero** and **strictly
  increasing per sender in the cluster frame**. Senders derive it as
  `max(wall_clock_ms_since_epoch, last_sent_ts + 1)`.
- `sequence` field is **removed**. Saves 8 B/packet.

**Witness state additions:**
- Per cluster: `cluster_offset_ms: i64`. Learned at BOOTSTRAP from the
  first node's `timestamp_ms`: `offset = node_ts - witness_uptime_ms`.
  Updated on each heartbeat (EWMA or latest-wins).
- Per node: `last_rx_timestamp_ms: i64` (the cluster-frame ms of its
  last-accepted heartbeat). Only updates with strictly-later values.

**Witness reply generation:**
- Output `timestamp_ms = witness_uptime_ms + cluster_offset_ms`.
  The witness is now emitting cluster-frame wall-clock ms without ever
  having had an RTC — it synthesizes the frame from node-provided time.

**What this buys:**
- Anti-replay is tied to wall-clock monotonicity in the cluster's frame.
  Witness reboot loses `cluster_offset` but re-learns from the next
  BOOTSTRAP; captured packets' `timestamp_ms` values are still from the
  past in cluster frame, so replay attempt "looks old" immediately —
  closing the witness-reboot replay window.
- Unit consistency (ms everywhere, including `last_seen_ms`).
- Multiple clusters served by one witness can have wildly different
  time frames (cluster A on real 2026, cluster B on retro-lab 1990
  time, cluster C on simulation 2099 time) — each cluster's time is
  private to it, never leaks to another, never collides.
- Saves 8 B/packet (the whole `sequence` field).

**What it costs:**
- Nodes MUST have wall-clock-ms (non-zero, sync'd). For our deployments,
  this is fine — nodes are Linux hosts running DRBD/Raft/etc., always
  have ntpd. But it forecloses "no-RTC sensor class node" use cases
  (none in our roadmap).
- Witness ESP32 timer drift matters. `esp_timer_get_time()` uses the
  40 MHz crystal on Olimex ESP32-POE-ISO at ~±20 ppm → ~1.7 s drift per
  24 h worst case. Between 3-s heartbeats, drift is ~60 μs (negligible).
  Over a 72 h idle node, ~5 s drift accumulates. Mitigation: update
  `cluster_offset` on every heartbeat; reply-timestamps stay aligned
  with the most recent sender.
- Implementation: +~30 lines of C (witness-side offset bookkeeping).

### 3.3 Per-cluster frame with asymmetric adaptation

**The right framing is per-cluster, not per-sender.** Nodes within a
cluster are by definition time-synchronised (they run NTP/chrony; this is
a cluster-ops requirement already). If a node's clock is wildly out of
sync with its peers, that cluster has an operational problem that the
witness cannot and should not paper over. One bad node's timestamps
either get rejected at the witness or the cluster-frame adapts away from
reality — either way, the failure is visible and resolvable at the
cluster layer.

**Asymmetric offset adaptation is the key insight:**

```
On incoming packet with timestamp T_pkt in cluster C:
  expected = witness_uptime_ms + C.cluster_offset
  delta    = T_pkt − expected

  if delta > 0:                           # packet is ahead of cluster frame
      C.cluster_offset += delta           # jump forward freely
  elif delta > −MAX_BACKWARD_JUMP_MS:     # packet slightly behind
      C.cluster_offset += max(delta, −MAX_BACKWARD_STEP_MS)
                                          # adapt backward at most 10 ms per pkt
  else:                                   # too far behind (e.g. > 1 s stale)
      drop silently
```

Proposed constants:
- `MAX_BACKWARD_JUMP_MS = 1000` — packets further than 1 s behind the
  cluster frame are rejected as implausible (clock-broken node, replay
  attempt, or cluster-wide NTP disaster that the cluster layer should
  handle, not the witness).
- `MAX_BACKWARD_STEP_MS = 10` — cluster frame can only drift backward at
  a capped rate. At 3 s heartbeat interval, that's ~3.3 ms of backward
  adaptation per real second — enough to absorb routine NTP corrections
  (a few hundred ms of skew is absorbed in ~a minute), too slow to
  facilitate a replay-rewind attack.

**Per-node anti-replay (simpler half):**

Per sender, witness stores `last_rx_timestamp_ms` (the cluster-frame
timestamp of the last accepted heartbeat). Next heartbeat from that
sender must have strictly-greater timestamp. This subsumes `sequence`
entirely — if `timestamp_ms` is the monotonic marker, the separate
`sequence` field is redundant and can be removed (saving 8 B/packet).

### 3.4 What this closes and what remains

**Closes: the post-witness-reboot replay window in the common case.**

Current (sequence-based):
- Witness reboots. Real BOOTSTRAP sets `last_rx = 0` for sender.
- Attacker replays a captured HEARTBEAT with seq > 0 → accepted.
- Replay overwrites state until real node's next heartbeat catches up.
- Window: ~3 s (one heartbeat interval).

Proposed (per-cluster wall-clock + per-sender strict-increasing):
- Witness reboots. Real BOOTSTRAP sets `cluster_offset` to current
  wall-clock ms (derived from BOOTSTRAP's `timestamp_ms`).
- Attacker replays a captured HEARTBEAT whose `timestamp_ms` is from
  before reboot → in cluster frame, that's > 1 s in the past → dropped.
- Window: **zero**.

**Does not close: the BOOTSTRAP-replay window.**

- If attacker replays a *BOOTSTRAP* before any real activity, the replay
  sets `cluster_offset` to the captured-time-in-past.
- Subsequent HEARTBEAT replays (from the same capture session) fit in
  that past frame → accepted.
- Real node eventually BOOTSTRAPs or heartbeats with current wall-clock.
  Because adaptation is forward-free, the frame jumps forward in one
  step. From then on, replays rejected.
- Window: same ~3 s as today, but now requires a BOOTSTRAP capture
  (rarer than HEARTBEAT captures).

Net improvement: attackers who captured HEARTBEATs but not BOOTSTRAPs
lose their replay attack entirely. Attackers with full capture keep
the narrow window. Appendix A's advertise-verify-act pattern remains
the operational defence.

### 3.5 NTP on the witness — implementation choice, not protocol mandate

The protocol-mandated time source is `uptime + cluster_offset`
(per-cluster, learned from authenticated cluster heartbeats). Every
witness — including ESP32 — implements this. **The wire output is
identical** regardless of whether a witness has access to NTP or not.

A Linux witness running ntpd/chronyd MAY use its NTP-disciplined
wall-clock for **additional sanity checks** on incoming heartbeats —
e.g., reject heartbeats whose `timestamp_ms` differs from local NTP
wall-clock by more than 1 hour. This catches grossly-wrong senders
(broken clocks, bootstrap-replay attacks) without changing semantics
for clusters operating correctly.

ESP32 witnesses cannot do this check, but their cluster-offset
mechanism already protects against everything except first-bootstrap-
with-bad-clock — and that case is a cluster-ops problem (the cluster
should fix its NTP), not a protocol problem.

**Why NTP is not mandatory:**

- **Air-gapped / lab deployments** are real. A witness in a
  test-bench rack with no internet can still run Echo correctly.
- **ESP32 SNTP support** adds code size and a network dependency that
  isn't load-bearing for protocol semantics.
- **Cross-cluster side channel.** If the protocol *required* the
  witness to derive its time from NTP, and one cluster happened to
  control the NTP source the witness used (or could MITM that
  traffic), that cluster could influence time-related decisions in
  *other* clusters sharing the same witness. The cluster-offset
  design avoids this entirely: every cluster's time frame is learned
  from its own authenticated heartbeats only.

**Why NTP is not forbidden:**

- Linux witnesses get NTP for free; refusing to use it would be silly.
- Used only for sanity bounds, not for protocol output, NTP doesn't
  create wire-level divergence between implementations.

**Operator advice for shared-witness deployments:** if you're using a
single witness across multiple distrusting clusters, prefer one with
NTP enabled (Linux) — the NTP sanity bound provides defense-in-depth
against a misbehaving cluster member trying to skew the witness's
view via bad timestamps. For single-cluster or fully-trusted
deployments, ESP32 without NTP is equally fine.

### 3.6 Decided

**All changes adopted:**

1. **`sequence` field removed.** `timestamp_ms` (i64 ms since Unix
   epoch) becomes the mandatory monotonic anti-replay marker. Strictly
   increasing per sender. Sender implementations MUST derive it as:
   ```
   next_ts = max(wall_clock_ms_since_epoch, last_sent_ts + 1)
   ```
   Saves 8 B/packet.

**`payload_len` field removed.** Derivable from UDP length + msg_type
layout + inline length fields (block count for payloads). HMAC/AEAD
still cover the whole packet for integrity. Any inconsistency between
UDP length and derived structure = silent drop. Saves 2 B/packet.

**Inline count fields for parser-forward progress are kept.** The
distinction between `payload_len` (removed) and fields like
`num_entries` / `own_payload_blocks` / `peer_payload_blocks` (kept):

- `payload_len` was redundant with `msg_type` + the inline counts.
  The parser already knows the payload structure from msg_type; the
  outer length was derivable.
- `num_entries` (in STATUS_LIST) is itself *the* inline count — there
  is no other way for a forward-only parser to know how many entries
  to consume before reading the HMAC. Without it, parsers would need
  to look at UDP length and reverse-compute, inverting the natural
  front-to-back read flow.
- Same reasoning applies to `own_payload_blocks` in HEARTBEAT and
  `peer_payload_blocks` in STATUS_DETAIL.

The UDP-length cross-check still applies to all messages as a second
integrity path: after reading all declared fields and the trailer, the
expected total must equal UDP length. Mismatch → silent drop. Two
independent integrity paths (internal-count consistency + UDP
boundary).

**STATUS_LIST cap: 128 entries** (up from proposed 64). MTU math:
```
14 (header) + 8 (preamble) + 1 (num_entries) + 128 × 9 (entries)
  + 32 (HMAC) = 1207 B — fits in 1400 B MTU with 193 B slack.
```
Nice symmetry: 128 × 9 = 1152, matching the `own_payload` max size.
128 is 2-3× any documented real voter-cluster (MongoDB caps voters at
50; any deployed Raft ≤ 20; Corosync practical ≤ 32). Cap exists to
preserve the "1 datagram = 1 message, no IP fragmentation" invariant
— not an arbitrary limit.

**STATUS_LIST includes the caller's own entry.** Useful for
public-IP self-discovery (node behind NAT sees its public IP as the
witness does) and cleaner semantics ("LIST = all cluster members"
with no special case). 9 B cost per LIST reply is trivial at typical
cluster sizes. Self-entry's `last_seen_ms` near-zero doubles as a
witness-latency sanity check for free.

**Combined `status_and_blocks` byte in STATUS_DETAIL.**

Packs what were two bytes (found/not-found status + block count) into
one byte, while preserving forward-compat capacity for future flags:

```
bit 7  (0x80):  status          0 = found, 1 = not found
bit 6  (0x40):  reserved flag   senders MUST zero, receivers
                                MUST ignore (NOT drop on non-zero)
bits 5-0 (0x3F):
    when bit 7 = 0 (found):     block count 0..36 (valid), 37..63
                                silent drop
    when bit 7 = 1 (not found): reserved future flags
                                (e.g., "witness in cleanup mode",
                                "aged out vs never seen", etc.)
                                senders MUST zero, receivers
                                MUST ignore
```

**Byte-value disposition:**

| Byte range | Interpretation | Echo behavior |
|---|---|---|
| 0x00..0x24 | found, N blocks of peer_payload follow | normal |
| 0x25..0x3F | invalid (bit 6=0 but bad count) | silent drop |
| 0x40..0x64 | bit 6=1 (forward-compat flag), N blocks with N=B&0x3F | extract N, process normally (if N≤36) |
| 0x65..0x7F | bit 6=1 + bad count | silent drop |
| 0x80..0xFF | not found (any reason flags in bits 0-6) | treat as not-found, ignore other bits |

**Side-effect benefit:** `peer_payload` starts at offset 32 — 32-byte
aligned. `peer_ipv4` and `peer_seen_ms_ago` at offsets 24 and 28 —
4-byte aligned. Free alignment from principled byte-packing.

**Two-point forward compat** vs the rejected header `reserved` byte:

- The rejected byte was MUST-be-zero with no defined meaning, meaning any
  future use would break parsers. Filler with a trap.
- `status_and_blocks` has defined meaning in bits 7 and 5-0. Bits
  6 (found-case flag) and 0-6 (not-found-case reason flags) are
  **defined-as-ignored**, so v2 extensions setting them don't
  break parsing. Principled capacity, not filler.

Future extensions through new `msg_type` values remain the primary
extension point (principle 8). The flag-bit reservation is a
secondary extension mechanism for signaling that must ride inside
existing reply types.

**`reserved` byte removed.** The "MUST be 0x00 now, upgrade to flags
later" story is self-contradictory: any implementation following
MUST-be-zero would drop a future non-zero packet, so no upgrade
is possible without breaking wire compat. `msg_type` (1 B = 256
values, 6 in use) is the real extension point. Saves 1 B/packet.

**`sender_id` shrinks to 1-2 B, with collision-resolution semantics**
(user's insight — original design relied on sender_id uniqueness,
which was statistical and scaled poorly):

- Witness may hold multiple node entries sharing the same sender_id,
  distinguished by cluster_key.
- Witness lookup is **IP-first, then sender_id, then HMAC**:

  ```
  candidates = nodes where sender_ipv4 matches packet src IP
  candidates = candidates where sender_id matches
  for c in candidates: if hmac_verify(pkt, c.cluster_key): accept
  else: UNKNOWN_SOURCE (rate-limited)
  ```

  The witness already stores `sender_ipv4` per node (learned from
  UDP source). IP-first filtering reduces the candidate set
  dramatically in realistic topologies (typically 1-3 nodes per IP
  outside corporate NAT).

- On BOOTSTRAP: if no existing (ip, sender_id, cluster_key) triple
  matches, create a new entry. Old entries coexist and age out
  independently.
- Correctness is cryptographically determined (HMAC match), not
  statistical.

**Size choice: 1 byte, decided.**

Cluster-internal node identifiers in real systems are overwhelmingly
small integers: Corosync `nodeid` is u32 but typical values are 1-32;
ZooKeeper `myid` is operator-assigned 1-N (rarely > 10); DRBD's
`node-id` is 0-based (`node-id 0; node-id 1;` in resource config);
MongoDB replica set members use 0-indexed `_id`; Pacemaker maps names
to Corosync's 1-32. Echo's STATUS_LIST caps clusters at 64 nodes per
datagram, so a 1-byte sender_id (values 0x00..0xFE, with 0xFF reserved
for the witness) gives 4× headroom over the cap while accommodating
both 0-indexed and 1-indexed native node-id conventions.

Cross-cluster collisions — multiple clusters on one witness
independently choosing `sender_id = 1` for their first node — are
expected and handled by the IP-first lookup + HMAC-trial chain.
In practice, with IP-first filtering reducing the candidate set to
~1-3 nodes in realistic topologies, collisions almost never trigger
fallback scans.

**Added benefit of collision resolution:** cluster-key "rotation"
works naturally — bootstrap with new cluster_key just creates a new
entry next to the old one. Old ages out. No coordination.

**Header total: 14 bytes** (down from original 32 B — 18 B saved):

```
Offset  Size  Name          Type    Description
──────────────────────────────────────────────────────────
0       4     magic         bytes   "Echo" = 0x45 0x63 0x68 0x6f
4       1     msg_type      u8      dispatch + layout selector
5       1     sender_id     u8      0..254 (0xFF reserved for witness)
6       8     timestamp_ms  i64     strict monotonic per sender
──────────────────────────────────────────────────────────
Total: 14 bytes
```

No filler, no reserved, no derivable fields. Every byte load-bearing.

**Witness sentinel at 0xFF, not 0x00.** Rationale:

| System | Native node-id starts at |
|---|---|
| DRBD 9 | **0** (`node-id 0; node-id 1; ...`) |
| MongoDB replica set | **0** (`members[0]._id = 0`) |
| Corosync | 1 (0 reserved/invalid) |
| ZooKeeper | 1 |
| Pacemaker | inherits Corosync (1+) |

Reserving `0x00` for the witness would force DRBD and MongoDB
operators to add a +1 offset when mapping their native node-ids to
Echo sender_ids. Reserving `0xFF` costs nothing: no cluster system
assigns 255 as its first or early node-id, and 255 is the natural
"sentinel / all-bits-set / max-u8" convention in byte-level
protocols. Both 0-indexed (DRBD, MongoDB) and 1-indexed (Corosync,
ZK) systems use their native IDs without translation.

Nodes use sender_ids `0x00..0xFE` (255 values — still 4× MongoDB's
50-voter cap, 30× any actually-deployed Raft cluster, and well
beyond Bedrock's STATUS_LIST cap of 64 entries).

Any node seeing an incoming packet with `sender_id = 0xFF`
immediately knows "this is from a witness, not a peer."

### 2.3 Witness implementation moved to its own doc

The witness-side normative behavior (IP-first lookup, collision
resolution algorithm, block allocator, defrag, NAT handling, timing
strategies, conformance checklist) now lives in
`docs/witness-implementation.md`. `PROTOCOL.md` stays a pure
wire-format spec; anything that's "how the witness stores or
processes state" lives in the implementation guide.

Rationale: several new-reference-implementation authors (the goal is
4+ cross-language implementations for protocol hardening) will want
to read PROTOCOL.md to understand the wire format, then reference
the implementation guide for the witness patterns. Keeping them
separate avoids polluting the wire spec with implementation
guidance that only matters to one side of the conversation (the
witness — nodes have much simpler implementation requirements).

2. **Senders MUST have sync'd wall-clock.** NTP/chrony/equivalent. Not
   a restriction for our target deployments (all nodes are Linux
   cluster hosts).

3. **`last_seen_seconds` → `last_seen_ms`.** u32 ms, same field size,
   1000× resolution. Fits 72 h age-out cap easily (u32 ms ≈ 49 days
   max).

4. **Witness-side time implementation is a free choice, not a protocol
   mandate.** Two valid implementation paths give identical wire
   output:

   - **Linux path (recommended for Linux witnesses):** use NTP-
     disciplined wall-clock directly via `clock_gettime(CLOCK_REALTIME)`.
     Emit as `timestamp_ms` in replies. Optional: sanity-bound incoming
     heartbeat timestamps against local wall-clock (reject if > 1 h
     differ). Defense-in-depth for multi-cluster shared-witness
     deployments.

   - **ESP32 path (for witnesses without real-time clock):** maintain
     a per-cluster `cluster_offset_ms` (i64). Learn it on first
     authenticated packet per cluster: `offset = pkt_ts - uptime`.
     Update on each heartbeat with asymmetric adaptation — forward
     freely, backward at most 10 ms/packet, reject if > 1 s behind
     cluster frame. Emit `timestamp_ms = uptime + cluster_offset` in
     replies. Per-sender `last_rx_timestamp_ms` (in cluster frame) is
     the anti-replay store; new packets must have strictly-greater
     timestamp.

   Both paths prevent cross-cluster time leakage: Linux uses its own
   NTP (external to any cluster); ESP32 learns each cluster's frame
   from its own authenticated heartbeats only.

**Explicitly rejected:** mandatory witness-side NTP (see §3.5).

---

## 4. Payload-size vs RAM-shape tradeoff on ESP32

Big-profile constraints (ESP32-POE-ISO, 180 KB DRAM):

| Payload max | N nodes | Payload RAM | Heap remaining (after ~15 KB state scaffolding) |
|---:|---:|---:|---:|
| 128 B | 256 | 32 KB | ~120 KB |
| 128 B | 512 | 64 KB | ~88 KB |
| **256 B** | **256** | **64 KB** | **~88 KB** |
| 256 B | 128 | 32 KB | ~120 KB |
| 512 B | 128 | 64 KB | ~88 KB |
| 1024 B | 64 | 64 KB | ~88 KB |
| 1024 B | 256 | 256 KB | **doesn't fit** |

If we adopt 256 B (option 2.1), the natural ESP32 profile becomes
**256 nodes × 256 B = 64 KB payload storage + ~10 KB other state + ~10 KB
scaffolding = ~85 KB total → ~95 KB heap**. Generous.

Smaller witnesses (NanoKVM Lite, Linux VM) trivially support any size —
this sizing is driven entirely by the ESP32 constraint.

---

## 5. Deployment guidance

(Collected here so `PROTOCOL.md` stays abstract.)

### 5.1 Witness redundancy

Run N = 3 or 5 witnesses on separate failure domains. Configure node daemon
with the list; daemon applies majority rule across witness views before
making any consequential decision. Witness failure is then tolerated up to
⌊(N−1)/2⌋ simultaneous failures.

### 5.2 Clock discipline for nodes

All nodes in a cluster MUST have sync'd wall-clocks (NTP or equivalent)
with skew under 1 s. The protocol's `timestamp_ms` field is the
anti-replay primitive — without a real wall-clock, a sender cannot
produce strictly-monotonic timestamps that survive restarts.

### 5.3 Heartbeat interval

Not mandated by the protocol (daemon-layer concern). Recommended
default: **2 s heartbeat × 5 miss threshold = 10 s failover detection**.

Rationale:
- 2 s is tight enough that one lost packet doesn't push you to 2/3 of
  the declare-dead threshold (as 3 s × 3 miss would).
- 5 miss gives resilience to transient packet loss on busy LANs.
- 10 s failover is comfortably inside typical cluster-layer dead-time
  budgets (Pacemaker defaults ~20 s, Corosync tokens ~3-5 s).
- Load on hosted witness: 10 K clusters × 2 nodes × 0.5 pps = 10 K
  pps, ~10 Mbps — trivial for a t4g.nano-class instance.

Variations:
- Low-traffic / battery-backed witness deployments: 3-5 s interval,
  3-4 miss. Slower failover, less witness load.
- High-availability write-path clusters that cannot afford 10 s of
  ambiguity: 1 s × 10 miss. Same 10 s failover, more resilient to
  burst packet loss at the cost of 2× witness load.

### 5.4 Cluster-key provisioning

Distribute cluster_key via out-of-band secure channel (configuration
management tool, provisioning system). Do NOT derive it from hostnames or
other predictable inputs. Generate with a cryptographically secure RNG.
32 bytes of real entropy.

### 5.5 Witness placement

Third failure domain — ideally different power feed, different network
switch, different rack/room/building depending on stakes. The whole
point of the witness is to be *not* what can fail together with either
cluster node.

---

## 5.5 DISCOVER msg_type for clean witness probing

Added `0x04 DISCOVER` (node → witness, unauthenticated, 14 B
header-only). Witness responds with the existing `0x10 UNKNOWN_SOURCE`
(46 B with pubkey).

**Why a dedicated msg_type rather than HEARTBEAT-with-bad-HMAC:**

Both flows produce the same outcome (UNKNOWN_SOURCE with pubkey),
but DISCOVER is cleaner:

| | HEARTBEAT-with-garbage | DISCOVER |
|---|---|---|
| Node-side cost | Construct fake cluster_key + HMAC | None (just header) |
| Witness-side cost | Lookup + HMAC verify before discarding | Zero — direct dispatch to UNKNOWN_SOURCE |
| Semantic clarity | Looks like genuine auth failure | Clearly a discovery probe |
| Operator log signal | Ambiguous | Distinct |

Use cases:
1. Dashboard discovery flow: probe N candidate witnesses, collect
   pubkeys, present to operator for TOFU verification.
2. Latency measurement: measure end-to-end witness RTT including
   service-layer latency (more meaningful than ICMP, which is also
   often firewalled in cloud environments).
3. Liveness check before BOOTSTRAP: confirm witness is reachable
   before committing a cluster_key.
4. Monitoring: Bedrock-side dashboards continuously probe witness
   set for availability.

**Same UNKNOWN_SOURCE rate limit applies** — 1 reply per second per
src IP regardless of whether trigger was DISCOVER or auth-failure.
Floods of DISCOVERs cannot generate floods of UNKNOWN_SOURCE replies.

DISCOVER is optional in the protocol — automated provisioning with
full DNSSEC trust can BOOTSTRAP directly using DNS-listed pubkeys
(see witness-implementation.md §6.1). DISCOVER exists for
operator-UX, latency, and liveness scenarios.

## 5.6 UNKNOWN_SOURCE carries the witness pubkey

UNKNOWN_SOURCE is 46 bytes: 14 B header + 32 B `witness_pubkey`. The
pubkey enables a **discovery workflow** that the prior empty-payload
design didn't:

```
Dashboard-driven witness provisioning:
  1. Operator picks candidate witness addresses (from provider list).
  2. For each, dashboard sends a HEARTBEAT with throwaway cluster_key.
  3. Witness replies UNKNOWN_SOURCE with its pubkey.
  4. Dashboard displays pubkey + fingerprint per candidate.
  5. Operator cross-checks against provider's published keys.
  6. Operator approves; cluster is provisioned with those pubkeys.
```

No new msg_type needed — the existing HEARTBEAT + UNKNOWN_SOURCE path
handles discovery.

**Authentication posture:**
- The pubkey is **not cryptographically authenticated in transit** — no
  shared key exists yet, so we can't HMAC or sign.
- First-use: TOFU with operator visual verification against
  out-of-band source (provider website, QR code, documentation).
- Steady-state: node compares UNKNOWN_SOURCE's pubkey against its
  configured pubkey. Mismatch → silent drop + operator alert
  (catches MITM, accidental reinstall, or misconfig).
- **Side-benefit: self-diagnostic for pubkey misconfig.** A node whose
  BOOTSTRAP attempts silently time out can fall back to sending a
  garbage heartbeat, receive UNKNOWN_SOURCE with the real pubkey,
  compare against its configured pubkey, and surface "you have the
  wrong witness pubkey configured" as a diagnostic.

**Cost:** 32 extra bytes per UNKNOWN_SOURCE reply, bounded by
1/s/src-IP rate limit. Negligible in aggregate.

**Amplification-reflection concern:** incoming ≥ 48 B HEARTBEAT →
outgoing 46 B UNKNOWN_SOURCE. Factor 0.96x, not an amplifier.

---

## 5.6.5 AEAD on every authenticated payload

All authenticated messages in the protocol use ChaCha20-Poly1305 AEAD,
not HMAC-SHA256. Decision rationale captured in §5.10 below; finalized
during BOOTSTRAP_ACK design.

Per-message:
- Encryption key: `cluster_key` (32 B), shared between cluster nodes
  and witness. (BOOTSTRAP itself uses an ECDH-derived ephemeral key
  because cluster_key is what's being delivered.)
- Nonce: 12 bytes, derived from header — `sender_id (1) || 0x000000
  (3) || timestamp_ms (8 BE)`. No nonce on the wire; receiver
  reconstructs from the same header bytes.
- AAD: the entire 14-byte header. Tampering with header invalidates
  the Poly1305 tag.
- Tag: 16 bytes. Replaces the 32-byte HMAC trailer of earlier drafts.

**Strict-monotonic-per-sender on `timestamp_ms` is now MUST-strict**
(not SHOULD): violating it causes nonce reuse and breaks the AEAD
guarantee, not just anti-replay. Nodes and the witness apply the rule
symmetrically. The witness's strict-monotonic counter is **per-cluster**
(implementation may choose per-witness-globally for simplicity at the
cost of faster timestamp drift).

**Per-message bytes saved vs HMAC-SHA256 trailer:** 16 bytes
(32 B HMAC → 16 B Poly1305 tag).

## 5.7 BOOTSTRAP and HEARTBEAT — separate roles

BOOTSTRAP creates the cluster on the witness (registers the
cluster_key). HEARTBEAT reports a node's state and, if the witness
doesn't yet know that node, joins it to its cluster.

**Node startup flow:**
```
Node has cluster_key from operator provisioning.
Try HEARTBEAT first.
  If reply (STATUS_LIST or STATUS_DETAIL): we're in. Done.
  If UNKNOWN_SOURCE: cluster doesn't exist on this witness yet.
    BOOTSTRAP to register the cluster_key.
    Then HEARTBEAT.
```

The node doesn't need to know whether it's the first or the Nth node
of its cluster. It just attempts the lighter operation first.

**Witness lookup adds one fallback path:**

Unrecognized HEARTBEAT (no entry for this sender_id) → before giving
up, try HMAC against every known cluster_key. If a match is found,
this is a new node joining an existing cluster: allocate a node
entry under that cluster, dispatch normally.

Cost: O(N_clusters) HMAC verifies for unrecognized HEARTBEATs.
Steady-state lookup unaffected. Hosted-scale 10K-cluster witnesses
spend a few hundred ms of CPU per join event — these events are
rare (typically a few per cluster per day).

Optimizations (witness-implementation detail):
- Cache last-matching-cluster per (src_ip) for fast retry.
- Use IP locality / subnet correlation as a hint.

**Lifecycle clarifications:**

| Event | Activity |
|---|---|
| First node of new cluster starts | HEARTBEAT → UNKNOWN_SOURCE → BOOTSTRAP → HEARTBEAT |
| Subsequent nodes join | HEARTBEAT (witness scans all cluster_keys, finds match) |
| Witness reboot | All nodes BOOTSTRAP; first creates cluster, rest get idempotent ACK |
| Node entry ages out | Same as fresh join; HEARTBEAT scan path picks it back up |

**Result:** the typical node startup is **one round trip** (HEARTBEAT +
reply), not two (BOOTSTRAP + ACK + HEARTBEAT + reply). BOOTSTRAP is
exceptional, used only when needed.

## 5.8 BOOTSTRAP cryptographic design

**Purpose (succinct):** deliver a fresh 32-byte `cluster_key` from a
node to a specific witness, in a single one-way packet, such that:
1. Only that witness can decrypt it at the moment of delivery
   (confidentiality via X25519 ECDH to witness's static pubkey).
2. Each BOOTSTRAP uses a unique encryption key (per-message key
   freshness via ephemeral keypair on the node side).
3. The packet cannot be modified in transit without detection
   (integrity via Poly1305 tag).

**Plaintext is now just the 32-byte cluster_key.** Earlier designs
included an `init_payload` for state, but that conflated security
setup with state reporting. Removed: state arrives via the first
HEARTBEAT after BOOTSTRAP_ACK. BOOTSTRAP becomes single-purpose
and fixed-size.

**Why ECDH and not "just 32 bytes of random salt":** to encrypt
cluster_key for delivery to the witness, we need an encryption key
that both sides can derive but no one else can. With nothing
pre-shared between node and witness, the only inputs available are:
the witness's public key (known to attackers too), and any secret
the node generates locally. Random salt alone gives nothing the
witness can use to derive the same encryption key.

ECDH provides the missing piece: the node generates a throwaway
keypair, computes `mix(throwaway_secret, witness_public)`. The
witness computes `mix(witness_secret, throwaway_public)` and arrives
at the same value. The throwaway public is structured 32 bytes that
look random to outside observers but participate in this derivation.

Alternatives all worse for our deployment model:
- RSA-OAEP / Kyber / ElGamal: heavier primitives, not in every
  language's stdlib, fail the "common-denominator crypto" principle.
- Pre-shared key with witness: requires out-of-band registration
  channel; defeats UDP-self-service model.
- Multi-message handshake: requires conversation, breaks NAT
  punching and the answer-only witness model.

X25519 is fast — keypair generation is point multiplication on the
curve, ~50-100 µs on ESP32. No prime finding (that's RSA). Faster
than the HMAC we already do per HEARTBEAT.

**Wire format: 94 bytes fixed.**

```
14  header
32  eph_pubkey (X25519)
32  encrypted cluster_key
16  Poly1305 tag
```

**Crypto recipe:**
```
shared   = X25519(eph_priv, witness_pub)
aead_key = HKDF-SHA256(ikm=shared, salt=zero32,
                       info=b"bedrock-echo bootstrap", L=32)
nonce    = zero12  (safe: aead_key is unique per packet)
aad      = header[0..14]
ct||tag  = ChaCha20-Poly1305-Encrypt(aead_key, nonce, aad,
                                     plaintext = cluster_key)
```

**MUST: fresh ephemeral keypair per BOOTSTRAP.** Reuse causes
encryption-key reuse with zero nonce, which leaks plaintext XOR
across messages. Critical security requirement for senders.

**On forward secrecy (correction):** earlier drafts of this doc
claimed BOOTSTRAP provides forward secrecy. **It does not.** A
future compromise of the witness's static private key allows an
attacker to decrypt previously-captured BOOTSTRAPs and recover the
cluster_keys they delivered. True forward secrecy requires both
sides to contribute ephemeral keys, which is impossible in a
single-message protocol against a static recipient.

The ephemeral keypair on the node side provides **per-message key
freshness** (essential against multi-capture cross-correlation
attacks), not forward secrecy.

Operational compensation for the lack of forward secrecy:
- Cluster_key is used only to compute HMACs, not to encrypt content.
  Recovery of cluster_key from old BOOTSTRAPs lets an attacker
  forge future traffic, not retroactively read content (which was
  plaintext-with-HMAC on the wire anyway).
- Operator rotation of witness keypair invalidates future use of
  any cluster_keys captured under the old witness pubkey, by way
  of new BOOTSTRAPs into fresh cluster_keys.

**Witness state changes on successful BOOTSTRAP:**

- New (sender_id, cluster_key) pair → allocate new node entry,
  collision-resolution semantics (multiple nodes may share sender_id
  in different clusters, distinguished by cluster_key).
- Existing (sender_id, cluster_key) pair → idempotent re-bootstrap;
  status 0x01.
- Per-cluster `cluster_offset` updated using the same forward-free /
  backward-bounded adaptation rule as for HEARTBEAT.
- Per-node `last_rx_timestamp` set to MAX(existing, pkt.timestamp_ms)
  — preserves anti-replay monotonicity even across re-bootstraps.
- Initial `own_payload` is empty (allocated as zero blocks). Filled
  in by the node's next HEARTBEAT.

**Silent drop, not UNKNOWN_SOURCE reply, on AEAD failure.** Replying
would leak existence of an Echo witness to scanning attackers.

**No HMAC trailer.** Poly1305 tag IS the integrity guarantee.
Adding HMAC would re-prove the same thing redundantly.

See witness-implementation.md §2 for the full BOOTSTRAP-handling
state machine.

---

## 5.10 BOOTSTRAP_ACK design

**Purpose:** witness's authenticated confirmation that the BOOTSTRAP
succeeded and the cluster_key is registered. Implicitly authenticates
the witness to the node (only the legitimate witness could have
recovered the cluster_key from the BOOTSTRAP and used it to AEAD-
encrypt the ACK).

**Wire format: 39 bytes fixed.**

```
14  header (msg_type=0x21, sender_id=0xFF, timestamp_ms)
 9  encrypted plaintext: status (1) + witness_uptime_ms (8)
16  Poly1305 tag
```

**Status byte (forward-compat pattern):**

```
bit 0:    0 = new entry created
          1 = idempotent re-bootstrap (cluster_key was already present
              for this sender_id)
bits 1-7: reserved. senders MUST zero. receivers MUST ignore
          upper bits (don't drop on non-zero).
```

Future use of bits 1-7 is for informational signals that receivers
can safely ignore (e.g., "witness in cleanup mode," "shared with N+
clusters"). Same forward-compat pattern as STATUS_DETAIL's status byte.

**Why only status + uptime:** every other field considered (cluster
size, slot index, witness pubkey echo, suggested heartbeat interval)
is either redundant with subsequent STATUS replies or leaks
implementation details. The minimal payload is what the protocol
needs.

**`witness_uptime_ms` is the one piece of information the node uses
operationally:** it lets the node detect a witness reboot by comparing
to previously-seen values from the same witness.

---

## 5.11 Items flagged for later review

These are accepted for in their current form, but the user has
flagged them for explicit reconsideration before finalising the spec.

### 5.11.1 New-node-join scan cost on the witness

The decision in §5.7 to let new nodes join an existing cluster
via a regular HEARTBEAT (with the witness scanning all cluster_keys
on no-IP-no-sender-id-match) introduces a per-event cost of
O(N_clusters) HMAC verifies. At hosted scale (10 K clusters), each
scan is ~100 ms of CPU.

A motivated attacker controlling many spoofed source IPs (or many
real IPs in a botnet) could flood unrecognised HEARTBEATs and force
repeated scans — potentially DoS the witness's scan budget.

**Mitigations available without protocol change:**
- Per-IP rate-limit the expensive scan path (e.g., 1 scan per IP per
  minute), separate from the general per-IP packet rate-limit.
- Per-IP cache of last-matching-cluster, so subsequent HEARTBEATs
  from the same IP try the cached cluster_key first (1 HMAC) before
  falling through to scan.
- Total-scans-per-second-across-all-IPs ceiling on the witness.

**Mitigation requiring protocol change (rejected, recorded
for review):** revert to "every node BOOTSTRAPs at startup," which
removes the scan path entirely but adds a round trip to every node
startup.

**Status:** keep §5.7 design as-is. Treat the scan-DoS as a
witness-implementation problem to solve via rate-limiting and
caching. Revisit if real-world deployment shows the implementation
mitigations insufficient.

### 5.11.2 Encryption coverage — RESOLVED, see §5.6.5

**Resolved during BOOTSTRAP_ACK shaping:** all authenticated payloads
now use ChaCha20-Poly1305 AEAD with cluster_key, not HMAC-SHA256.
Saves 16 B/packet, gains payload confidentiality, reduces the protocol
to one symmetric primitive. See §5.6.5.

---

## 6. Known limitations (not gaps)

- **IPv4 only.** The header carries no IP field (source IP
  comes from UDP/IP); only `peer_ipv4` (4 B) in STATUS_LIST and
  STATUS_DETAIL is IPv4-bound. IPv6 ships as new msg_type values
  (e.g. `STATUS_LIST_V6 = 0x04`, `STATUS_DETAIL_V6 = 0x05`) carrying
  16 B addresses. No wire-format bump; msg_type is the extension
  point per principle 8. Witnesses that support IPv6 can track both
  address families in storage; witnesses that don't simply never
  emit the V6 msg_types.
- **No payload confidentiality.** HEARTBEAT payloads are authenticated
  (HMAC) but not encrypted. Apps needing payload secrecy must encrypt at
  the application layer before putting bytes in `own_payload`. Documented
  as intentional in §14.
- **Single cluster_key per cluster.** Compromise of any node leaks
  HMAC-forgery capability for the whole cluster. Acceptable for LAN
  deployments where hosts are equally trusted; not acceptable for
  zero-trust models. See §14.

---

## 7. Anti-amp + cookies polish (post-Phase-4)

After Phase 4 (cross-language interop verified live, 117 tests passing)
the user pushed back on three weaknesses I had filed as "operational
issues" rather than protocol issues:

1. **Amplification.** The original DISCOVER was 14 B, the
   UNKNOWN_SOURCE reply was 46 B → ~3.3× amplification factor. A
   bot-net spoofing victim IPs could turn the witness into a UDP
   reflector. "Operational compensation" via per-IP rate limit only
   reduces the magnitude, not the existence of the vulnerability.

2. **Cluster_key alone is 0 security from the witness's POV.** An
   attacker can pick *any* random 32-byte string, call it
   `cluster_key_attacker`, and BOOTSTRAP a brand-new cluster on the
   witness with arbitrary src_ip. The witness installs the cluster.
   This is an open-ended packet injection: with only the witness's
   pubkey (which is public), an off-path attacker can spam cluster
   creations, exhaust state, or — worse — spoof the BOOTSTRAP source
   IP and use the witness as an amplifier toward the spoofed victim.

3. **Sender_id-only fallback in HEARTBEAT** allowed an off-path
   attacker who guessed (sender_id, cluster_key) — or just guessed
   sender_id within an existing cluster they happen to know the key
   of — to redirect the legitimate node's stored `sender_ipv4` to the
   attacker's address. From then on, replies for that node go to the
   attacker. The cluster_key membership requirement narrows the attack
   surface but doesn't eliminate it (insider attack, or post-leak).

### 7.1 The fix: DNS-cookie-style bind-to-IP on BOOTSTRAP, drop fallbacks

Three coupled changes:

- **DISCOVER → INIT request size = INIT reply size.** DISCOVER pads
  to 62 B (zero-filled), INIT is 62 B (14 B header + 32 B pubkey +
  16 B cookie). Amplification factor: exactly 1.0×.

- **INIT carries a DNS-style cookie.** `cookie =
  SHA-256(witness_cookie_secret || src_ip)[:16]`. The witness rotates
  `witness_cookie_secret` hourly and keeps current+previous, giving
  cookies a ~2 h validity window. The cookie is **not secret**; it's
  a short MAC over src_ip under a witness-only key. Its job is to
  force any BOOTSTRAP sender to prove they actually received an INIT
  at the IP they're claiming.

- **BOOTSTRAP MUST carry a valid cookie**, validated under
  current-or-previous secret, and **strict (src_ip, sender_id) match
  is required for HEARTBEAT** (the sender_id-only fallback and the
  new-node-join-via-HEARTBEAT scan are both removed). All new node
  introductions go through cookie-validated BOOTSTRAP. IP changes
  (DHCP renewal) require re-BOOTSTRAP — costing two round-trips on
  a rare event but eliminating the off-path IP-redirect attack class.

### 7.2 Why "DNS cookies" specifically (vs alternatives considered)

- **HMAC-on-every-packet (a la TCP cookies).** Adds 16+ B to every
  HEARTBEAT — at hosted scale that's billions of bytes/day for what
  AEAD already provides (the cluster_key MACs every steady-state
  packet by construction). Rejected.

- **Stateful three-way handshake (a la TCP SYN cookies but with
  state).** Adds two round-trips and per-flow witness state. Defeats
  the "tiny RAM-only witness" goal. Rejected.

- **Puzzle-based proof-of-work.** Annoying for legitimate IoT-class
  nodes; not actually a defense against well-resourced attackers.
  Rejected.

DNS cookies (RFC 7873) are the right precedent: they are the same
"prove you can receive at this src_ip via a short stateless MAC"
construction, used for the same reason (stateless DDoS hardening),
adopted by the same kind of small-state-budget servers. Echo's
cookie is structurally identical with the obvious renames.

### 7.3 Why drop the new-node-join-via-HEARTBEAT scan

Pre-polish, a new node could join an existing cluster simply by
sending a HEARTBEAT under the right cluster_key — the witness would
trial-AEAD-decrypt against known cluster_keys and, on match, allocate
a node entry. This was elegant but allowed any holder of a leaked
cluster_key to inject node entries from arbitrary spoofed src_ips.

By forcing all new-node introductions through BOOTSTRAP, every node
in the witness's table has been cookie-validated for src_ip ownership
**and** demonstrated the cluster_key via AEAD — both, not just the
second. The cost is one extra round-trip on first cluster-join (which
also exists already on cold start), and a measurable reduction in the
witness's CPU cost of cluster scanning under load (the worst case
"AEAD-decrypt against every known cluster_key" path is gone).

### 7.4 What remains 0-security-against (and why we accept it)

- **Insider attack.** A node holding the cluster_key can forge any
  HEARTBEAT under that key, including ones with their own (legit)
  src_ip. Cookies don't prevent this; they aren't intended to.
  Cluster-internal trust is the operator's concern.

- **Replay of a captured BOOTSTRAP within the cookie window.** If
  an on-path attacker captures node-A's BOOTSTRAP, they can replay
  it within ~2 h. The replayed BOOTSTRAP hits the "existing entry"
  path (same sender_id, same cluster_key under AEAD) → idempotent
  ACK → the existing entry's `last_rx_timestamp` is already
  monotonically ratcheted past the captured timestamp_ms (per §6.3),
  so the replay is silently dropped. No state corruption.

- **Active MITM at the network layer.** Out of scope for any UDP
  protocol without TLS-style trust anchors. The DNSSEC pubkey-
  distribution path closes this for hosted-witness deployments.

### 7.5 Estimated cost

- Wire: +48 B on DISCOVER, +16 B on INIT, +16 B on BOOTSTRAP.
  These are one-time-per-cluster-membership events, so total bytes
  on the wire over the lifetime of a cluster increase by < 0.01%.
- Witness state: +64 B (2× witness_cookie_secret). No per-flow state.
- Witness CPU: +1 SHA-256 per BOOTSTRAP and per emitted INIT.
  Negligible (~µs).
- Code: ~50 LoC per implementation for cookie generation/validation/
  rotation. Plus deletion of the new-node-join scan and the
  sender_id-only fallback (net code reduction in the steady-state
  lookup path).

### 7.6 Decided

Yes, ship this before any external implementations
exist. The wire-format bumps for DISCOVER/INIT/BOOTSTRAP are isolated
to bootstrap-only message types — the steady-state HEARTBEAT and
STATUS_* formats are unchanged.
