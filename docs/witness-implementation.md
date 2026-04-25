# Bedrock Echo — witness implementation guide

This document describes how a conformant witness implementation handles
state, lookup, and dispatch. Some items are **normative** (required for
the protocol to work at scale or under adversarial input); others are
**recommended** (performance optimizations that don't affect wire
semantics). `PROTOCOL.md` is the wire contract; this document is the
witness-side manual.

---

## 1. Packet ingress and lookup

### 1.1 Lookup order (NORMATIVE)

On incoming UDP datagram:

```
1. Validate UDP length ≥ 14 (header size).
2. Parse and validate fixed header (magic, msg_type known).
3. Route by msg_type:
     - DISCOVER   (0x04):        validate length == 62, MAY check
                                  zero-padding; emit rate-limited INIT
                                  (with fresh cookie for src_ip).
     - BOOTSTRAP  (0x20):        validate length == 110; § 2
                                  (bootstrap path — cookie-validated).
     - Other authenticated:      § 1.2 (steady-state path).
     - INIT       (0x10):        silently drop (witness-emitted,
                                  node-ignored on inbound).
```

### 1.2 Steady-state authentication (NORMATIVE)

For HEARTBEAT and other AEAD-authenticated inbound types:

```
src_ip = source IP from UDP header
sid    = sender_id from Echo header

candidates = nodes where
    node.sender_ipv4 == src_ip AND node.sender_id == sid

if candidates is empty:
    rate-limited INIT reply (witness has no entry for this caller).
    DO NOT fall back to a sender_id-only scan; DO NOT attempt the
    new-node-join AEAD scan. See §1.4 and design-notes §7.

for c in candidates (optimization order, § 1.3):
    if aead_decrypt(packet, c.cluster_key) succeeds:
        update c.last_rx_timestamp, c.last_rx_ms, c.sender_src_port
        dispatch to handler for msg_type
        return

no candidate verified → rate-limited INIT reply
```

The strict (src_ip, sender_id) match is **mandatory**, both for
performance (otherwise sender_id scans degrade to O(N_total_nodes)) and
for security: an off-path attacker spoofing the source IP cannot redirect
or hijack an existing node entry's stored payload, because the witness
will never AEAD-decrypt the packet against the legitimate node's
cluster_key for a non-matching src_ip. (An IP change such as DHCP
renewal requires a re-BOOTSTRAP; see PROTOCOL.md §13.4.)

### 1.3 Per-(src_ip, src_port) candidate cache (RECOMMENDED)

For each known `(src_ip, src_port)` tuple, cache the index of the
most recently AEAD-verified node entry. On subsequent packets from
the same tuple, try that entry first before scanning siblings.

Steady-state cache hit rate is ~100% (nodes don't change cluster
between heartbeats, and their source port is stable for the lifetime
of their socket). This reduces the hot-path cost from "scan bucket,
try each AEAD decrypt" to "single AEAD verify" regardless of bucket
size.

Cache invalidation: on AEAD failure for the cached entry, fall
back to the full candidate scan and update the cache with whatever
matches.

Cache sizing: one slot per active `(src_ip, src_port)` is enough.
LRU-evicted when full. A hosted witness serving 10 K clusters sees
~30 K tuples; a 32 K-entry cache (~1 MB with 32 B/entry) fits
trivially on Linux. ESP32 witnesses can skip the cache entirely —
their candidate buckets are small enough that linear scan is fast.

This optimization is why DRBD-multi-resource-per-host deployments
(one Linux server running 50+ DRBD resources, thus 50+ distinct
Bedrock node processes on the same IP) don't cause witness CPU
blowup: each node process uses its own ephemeral source port, so
cache entries are per-process, and steady-state traffic hits the
cache directly.

### 1.4 New-node-join (NORMATIVE — via BOOTSTRAP only)

There is no HEARTBEAT-driven new-node-join path. A node whose
(src_ip, sender_id) doesn't match an existing entry receives a
rate-limited INIT and is expected to respond with a BOOTSTRAP. This
unifies all node-introduction events under the cookie-validated
BOOTSTRAP path, so every entry in the node table has demonstrated:

- **src_ip ownership** via the cookie round-trip (PROTOCOL.md §11.2),
- **cluster_key knowledge** via AEAD decryption of the BOOTSTRAP
  ciphertext (PROTOCOL.md §4.3).

Removing the HEARTBEAT-driven new-node scan also eliminates the
witness's worst-case O(N_clusters) AEAD-decrypt loop and closes the
"off-path attacker who knows a leaked cluster_key can inject node
entries from arbitrary spoofed src_ips" attack surface. See
design-notes §7 for the full rationale.

---

## 2. BOOTSTRAP path

### 2.1 Lookup + semantics (NORMATIVE)

```
1. Cookie pre-check (before any crypto):
   cookie_in        = packet bytes [14..30]
   src_ip_be        = 4 bytes from UDP source IP
   cookie_current   = SHA-256(witness_cookie_secret_current  || src_ip_be)[:16]
   cookie_previous  = SHA-256(witness_cookie_secret_previous || src_ip_be)[:16]
   if cookie_in != cookie_current AND cookie_in != cookie_previous:
       silent drop (or rate-limited INIT — implementation choice;
       both conformant per PROTOCOL.md §5.6).
       DO NOT proceed to AEAD decryption.

2. parse eph_pubkey, AEAD-decrypt ciphertext to recover plaintext.
   AAD = packet bytes [0..30] (header || cookie).
   plaintext = cluster_key (32 bytes)   ← this is all that's in there.
   AEAD failure → silent drop.

sid = sender_id from header
K   = recovered cluster_key

existing = nodes where sender_id == sid AND cluster_key == K

if existing:
    status = 0x01 (idempotent re-bootstrap)
    update existing.sender_ipv4 = src_ip
    update existing.sender_src_port = src_port
    update existing.last_rx_ms = uptime_ms
    update existing.last_rx_timestamp =
        max(existing.last_rx_timestamp, packet.timestamp_ms)
        # MAX preserves anti-replay monotonicity even if BOOTSTRAP is replayed
    update per-cluster cluster_offset using same forward-free /
        backward-bounded rule as for HEARTBEAT (PROTOCOL.md § 6.2)
else:
    # sender_id may collide with nodes in OTHER clusters — that's fine.
    # Create a new node entry; old ones coexist and age out.
    allocate new node entry n
    if allocation fails: silent drop
    populate:
        n.sender_id          = sid
        n.cluster_key        = K (link to cluster, find_or_create_cluster_for(K))
        n.sender_ipv4        = src_ip
        n.sender_src_port    = src_port
        n.last_rx_ms         = uptime_ms
        n.last_rx_timestamp  = packet.timestamp_ms
        n.payload_n_blocks   = 0   (no own_payload yet — comes via first HEARTBEAT)
    if cluster is new: K.cluster_offset = packet.timestamp_ms - uptime_ms
    status = 0x00 (new entry created)

reply BOOTSTRAP_ACK with status and witness_uptime_seconds
```

Note: BOOTSTRAP never silently drops on "sender_id exists with different
cluster_key." That's a collision, resolved by creating a new entry. The
pre-existing entry in a different cluster is untouched.

BOOTSTRAP no longer carries `init_payload`. The first HEARTBEAT after
BOOTSTRAP_ACK provides the node's initial state. Until then,
`payload_n_blocks = 0`.

### 2.2 Replay protection on BOOTSTRAP

BOOTSTRAP is idempotent: replaying the same packet recovers the same
cluster_key, hits the "existing entry" path, results in the same ACK.
No mutation. Per the MAX rule above, replay cannot roll back
last_rx_timestamp.

A replayed BOOTSTRAP after the entry was aged out would recreate the
entry. The recreated stale entry occupies state until it ages out
again. Bounded harm.

**MUST: senders generate a fresh X25519 ephemeral keypair for each
BOOTSTRAP** and discard the private key after encryption. Reuse
causes encryption-key reuse with zero nonce — see PROTOCOL.md § 4.3.

---

## 3. Node state model

### 3.1 Required fields per node entry

```
sender_id           u8            from the header
sender_ipv4         [u8; 4]       learned from UDP source
sender_src_port     u16           learned from UDP source (cache key)
cluster_slot        (u16 or ptr)  which cluster this node belongs to
last_rx_ms          u64           witness-monotonic ms of last accepted pkt
last_rx_timestamp   i64           last accepted timestamp_ms (anti-replay
                                  + AEAD nonce-uniqueness invariant)
last_tx_timestamp   i64           last witness-emitted timestamp_ms to
                                  this sender (per-cluster strict-monotonic)
payload_first_block u16           index into payload pool
payload_n_blocks    u8            number of 32-byte blocks allocated
                                  (0..36; 0 means no payload yet)
```

No `payload_len` field — the wire format is block-granular (N × 32
bytes exactly), so the witness stores exactly that many bytes and
serves them back unmodified. Applications embed their own length
metadata inside `own_payload` if they need byte-precision.

Cluster table separately holds:
- `cluster_key`    [u8; 32]
- `cluster_offset` i64       (per PROTOCOL.md § 6.2)
- `bootstrapped_ms` u64
- `num_nodes`      u8 (or larger)

Nodes reference their cluster by slot index.

### 3.2 Payload storage — block allocator (NORMATIVE for constrained impls)

Linux / general-purpose witnesses may use heap allocation for payload
storage. ESP32 / embedded witnesses SHOULD use a fixed block pool
with compaction (see § 3.3).

The block allocator provides deterministic memory, zero fragmentation
(after compaction), and predictable OOM behavior. Essentially required
for long-lived embedded deployments. 32-byte blocks are the right
granularity: small enough that 32-byte node payloads use 1 block
efficiently, aligned with cache lines, and divides our 1152-byte max
cleanly (36 blocks).

**Block allocator mechanics (no bitmap):**

The node table itself is the allocation map. To find N contiguous
free blocks: collect all `(first_block, first_block + n_blocks)`
intervals from in-use node entries, sort, scan gaps for first fit.

```c
int16_t alloc_blocks(state, n_blocks):
    intervals = sorted list of (node.first_block, node.first_block + node.n_blocks)
                for node in nodes if node.in_use
    cursor = 0
    for (start, end) in intervals:
        if start - cursor >= n_blocks:
            return cursor
        cursor = end
    if TOTAL_BLOCKS - cursor >= n_blocks:
        return cursor
    return -1  // no fit, caller should try defrag
```

Cost: O(M log M) per allocation where M = nodes-in-use. Negligible
at any realistic M.

### 3.3 Defragmentation (NORMATIVE for block-allocator impls)

On allocation failure when `sum(n_blocks) + n_requested ≤ TOTAL_BLOCKS`
(free space exists but is fragmented), run compaction:

```c
void defrag(state):
    intervals = sort nodes by first_block ascending
    cursor = 0
    for node in intervals:
        if node.first_block > cursor:
            memmove(pool + cursor*32,
                    pool + node.first_block*32,
                    node.n_blocks*32)
            node.first_block = cursor
        cursor += node.n_blocks
    // blocks [cursor, TOTAL_BLOCKS) are now all free, contiguous.
```

Always compacts toward the LOW end of the pool. Free space always
accumulates at the HIGH end. Same direction every time — no
alternation, no scratch reserve.

`memmove` handles overlap correctly (always shifts down into a
known-free region behind the cursor).

Worst-case defrag: one big memmove of the entire pool. On ESP32 with
a 36 KB pool, this is ~700 μs of CPU. Acceptable hiccup. Defrag
should run inline in the packet-handling task (synchronous with
receive, so node entries don't mutate mid-operation).

### 3.4 Payload resize (NORMATIVE)

When an existing node sends a heartbeat whose `own_payload` needs
more or fewer blocks than currently allocated:

```
if new_size ≤ current_size:
    write new payload into existing blocks (possibly shrink n_blocks)
    free trailing blocks (update n_blocks)
else:
    alloc_first = alloc_blocks(new_size_in_blocks)
    if alloc_first < 0 and defrag_would_help():
        defrag()
        alloc_first = alloc_blocks(new_size_in_blocks)
    if alloc_first < 0:
        silent drop (pool exhausted)
        // node entry keeps its previous smaller payload unchanged
    else:
        memcpy new payload to pool[alloc_first]
        free_blocks(node.first_block, node.n_blocks)
        node.first_block = alloc_first
        node.n_blocks = new_size_in_blocks
```

Silent drop on pool exhaustion is the universal failure response
(same as all other resource-exhaustion cases). Age-out tiers
accelerate pool reclamation under pressure — see § 5.

---

## 4. Anti-replay and timing

### 4.1 Per-sender monotonic timestamp (NORMATIVE)

Each node entry stores `last_rx_timestamp` (i64 ms). The check happens
**before** AEAD decryption — replay rejection should not require crypto.
But: the timestamp_ms field is in the (plaintext) header, so the check
is cheap regardless.

```
if packet.timestamp_ms <= node.last_rx_timestamp:
    silent drop (replay)

[then attempt AEAD decryption; if successful:]
node.last_rx_timestamp = packet.timestamp_ms
```

This is the sole wire-level anti-replay mechanism, and it is also
load-bearing for AEAD nonce uniqueness (the timestamp_ms is part
of the nonce derivation in PROTOCOL.md § 4.2). Senders MUST derive
`timestamp_ms` as `max(wall_clock_ms, last_sent + 1)`.

### 4.2 Witness time strategy — two valid paths

The protocol emits `timestamp_ms` in witness-generated replies.
Implementations have two conformant ways to produce this:

**Path A: NTP-disciplined wall-clock (Linux / general-purpose).**

Use `clock_gettime(CLOCK_REALTIME)` (Linux) or equivalent. Emit as
`timestamp_ms`. Optionally sanity-bound incoming heartbeats: reject
if `|packet.timestamp_ms − now| > 1 hour`. Provides defense against
misbehaving clusters skewing witness state.

**Path B: Per-cluster offset (ESP32 / clockless).**

Maintain `cluster_offset: i64` per cluster. Learn on first
authenticated packet: `offset = pkt.timestamp_ms − uptime_ms`.
Update on each accepted heartbeat with asymmetric adaptation:

```
delta = pkt.timestamp_ms − (uptime_ms + cluster.offset)

if delta > 0:
    cluster.offset += delta                     # forward freely
elif delta > -MAX_BACKWARD_JUMP_MS:             # -1000 ms
    cluster.offset += max(delta, -MAX_BACKWARD_STEP_MS)  # -10 ms/pkt cap
else:
    silent drop (packet too far behind cluster frame)
```

Emit `timestamp_ms = uptime_ms + cluster.offset` in replies. Nodes
can't distinguish this from NTP-based path.

### 4.3 NTP on the witness (RECOMMENDED for Linux, OPTIONAL for ESP32)

Linux witnesses get NTP essentially for free (ntpd/chronyd).
ESP32 witnesses can skip it — path B above doesn't require it.
Operators MAY configure NTP on ESP32 for log-timestamping purposes;
it does not affect protocol behavior.

**Do not make NTP mandatory**: an air-gapped witness (lab, dev,
isolated network) must still work. See design-notes §3.5 for
the cross-cluster side-channel argument against NTP-as-truth.

### 4.4 Timestamp in INIT replies (special case)

INIT is sent before any cluster relationship exists, so
the per-cluster offset path doesn't apply. The witness MAY use,
in order of preference:

1. NTP-disciplined wall-clock if available (Linux path).
2. `uptime_ms + cluster_offset` from any *other* cluster currently
   bootstrapped on this witness (the offset is per-cluster but
   approximately wall-clock for sane clusters; close enough for
   an informational field).
3. The `timestamp_ms` field from the incoming HEARTBEAT that
   triggered this INIT (the caller's claimed wall-clock,
   echoed back). Pure best-effort — caller may be lying or have a
   bad clock, but INIT is unauthenticated anyway.
4. Zero. Always acceptable; signals "no usable wall-clock available."

Receivers MUST treat INIT's timestamp_ms as informational
only — it is not authenticated and provides no security guarantee.

---

## 5. Age-out and resource reclamation (NORMATIVE)

The age-out tier policy from PROTOCOL.md § 10 applies independently
to two resources:

- Node table fill (# of in-use node slots / MAX_NODES)
- Block pool fill (sum of n_blocks / TOTAL_BLOCKS)

Use the more aggressive tier of the two:

```
tier = max(node_fill_tier, pool_fill_tier)
timeout_ms = tier_timeout[tier]

for node in nodes if in_use:
    if now_ms − node.last_rx_ms > timeout_ms:
        free_blocks(node.first_block, node.n_blocks)
        drop node entry
        decrement cluster.num_nodes
        if cluster.num_nodes == 0:
            drop cluster entry
```

Tier thresholds (per PROTOCOL.md §10):
- 0-80% filled: 72 h
- 80-90%: 4 h
- 90-100%: 5 min

### 5.1 Rate limiting (NORMATIVE)

Per source IP: token bucket, 10 packets/sec, burst 20. Packets over
the limit: silently drop. INIT replies additionally
rate-limited to 1/sec/src-IP.

Tracked IPs capped at ~192 slots (ESP32 big profile). When full,
evict oldest `last_refill_ms`. This is anti-flood hygiene for small
LANs; upstream firewalling is expected in production hosted
deployments.

---

## 6. Pubkey distribution (deployment recipe)

The protocol does not specify *how* a node obtains the witness's
X25519 pubkey out-of-band — that's deployment policy. INIT
includes the witness's pubkey in its 32-byte payload, but that
channel is unauthenticated and only useful as a verification check
against an authenticated source. Three deployment patterns:

### 6.1 DNSSEC-authenticated DNS records (recommended for hosted services)

Inspired by DKIM/SPF, witness pubkeys can be published as TXT
records on a DNSSEC-signed domain. This is the recommended
distribution channel for hosted-witness-service deployments.

Example zone for `echo.bedrock-it.com`:

```
_echo._udp.bedrock-it.com.  IN SRV 10 5 12321 eu1.echo.bedrock-it.com.
_echo._udp.bedrock-it.com.  IN SRV 10 5 12321 us1.echo.bedrock-it.com.
_echo._udp.bedrock-it.com.  IN SRV 10 5 12321 ap1.echo.bedrock-it.com.

eu1.echo.bedrock-it.com.    IN A    203.0.113.10
eu1.echo.bedrock-it.com.    IN TXT  "v=Echo; k=x25519; p=BASE64_PUBKEY"

us1.echo.bedrock-it.com.    IN A    198.51.100.10
us1.echo.bedrock-it.com.    IN TXT  "v=Echo; k=x25519; p=BASE64_PUBKEY"
```

**TXT format:**
- `v=Echo` distinguishes Echo records from other co-located TXT
  (SPF, DKIM, etc.). Future protocols use a different value.
- `k=x25519` declares key type. Future primitives use other values.
- `p=…` is the X25519 pubkey, 32 raw bytes encoded as base64
  (44 chars with padding, fits one TXT string).

**Key rotation:** publish multiple TXT records for the same name.
Clients accept any listed pubkey.

```
eu1.echo.bedrock-it.com.    IN TXT "v=Echo; k=x25519; p=NEW_BASE64"
eu1.echo.bedrock-it.com.    IN TXT "v=Echo; k=x25519; p=OLD_BASE64"
```

After rotation completes (witness has migrated to new privkey, all
clients see new pubkey via INIT), remove the old TXT
record.

**Client discovery flow:**

```
1. Operator types service domain: "echo.bedrock-it.com"
2. DNSSEC-validating resolver: SRV _echo._udp.bedrock-it.com
   → ranked list of (host, port) tuples
3. For each host: A/AAAA → IP; TXT → set of valid pubkeys
4. Send HEARTBEAT-with-garbage to each (IP, port)
5. Receive INIT; extract witness's claimed pubkey
6. Verify claimed pubkey ∈ DNS-listed pubkeys for that host
7. Match → present to operator as authenticated witness
   Mismatch → present as unverified (configuration drift or MITM
              candidate)
```

The cross-check between DNS-listed pubkey and INIT-reported
pubkey provides defense-in-depth: an attacker would need to compromise
both the DNSSEC chain *and* the network path.

**Trust model:** DNSSEC chain to the DNS root + TLD operator + zone
operator. Smaller trusted-party set than HTTPS-to-website-listing or
QR-code-on-packaging. Standard registry-grade infrastructure.

### 6.2 Configuration-management provisioning

For self-hosted clusters: distribute pubkeys via the same channel
that distributes other secrets (Ansible vault, Vault, SOPS-encrypted
config, etcd-backed config-management system). INIT's
pubkey is a verification check; the configured pubkey is authoritative.

### 6.3 Manual provisioning (smallest deployments)

Operator copies pubkey from witness's serial console output (printed
on first boot, persistent in NVS) into cluster config. INIT
serves as a "are these the same key?" sanity check.

### 6.4 Provisioning vs. discovery

These three patterns are not mutually exclusive. A typical hosted
deployment uses §6.1 (DNS-published pubkeys) for first-time
discovery and ongoing verification, while §6.2 (config-management)
might also push the resolved pubkey to nodes for offline-capable
operation.

---

## 7. NAT traversal (deployment note)

Echo is NAT-friendly by construction: the witness only replies,
never initiates. Nodes behind NAT send heartbeats outbound; NAT
allocates mappings; witness replies hit the live mapping. No NAT
configuration needed.

Heartbeat cadence keeps mappings alive. Most stateful NATs retain
UDP mappings for 30-120 seconds of idle. Default 2-second heartbeat
is well inside this; sparse-heartbeat deployments (30+ s intervals)
may see occasional first-packet-after-idle loss, healed by retry +
INIT re-bootstrap.

The hosted-witness service model (3-5 public-IP witnesses hosted
globally) works across arbitrary NAT topologies with zero
per-deployment configuration.

---

## 8. Sizing profiles

### 7.1 ESP32-POE-ISO (big profile)

| Item | Size |
|---|---:|
| Node table (512 × ~56 B) | ~29 KB |
| Cluster table (256 × 48 B) | ~12 KB |
| Rate-limit table (192 × 28 B) | ~5 KB |
| Block pool (1152 blocks × 32 B) | ~36 KB |
| ESP-IDF baseline | ~12 KB |
| **Total .bss** | **~94 KB** |
| **Heap remaining** | **~86 KB** |

Capacity: 512 tracked nodes / 256 clusters. Block pool supports
simultaneously 32 fully-fat (1152 B) nodes, 1152 single-block nodes,
or any combination.

### 7.2 Linux (t4g.nano hosted witness)

Natural sizing for ~30 K nodes × ~10 K clusters on the smallest AWS
instance:

| Item | Size |
|---|---:|
| Node metadata (30 K × 64 B) | ~2 MB |
| Cluster metadata (10 K × 48 B) | ~0.5 MB |
| Payload heap (avg 128 B × 30 K) | ~4 MB |
| Tuple cache (32 K entries × 32 B) | ~1 MB |
| **Total witness state** | **~8 MB** |

Well under the t4g.nano's 512 MB. CPU load at 10 K pps steady-state
(with tuple cache hot): ~10% of one vCPU. Bandwidth: ~10 Mbps. Scales
10× by switching to t4g.micro ($7.50/month).

### 7.3 Tiny profile (reference implementation testing)

Python reference implementation uses 64 nodes / 32 clusters /
128 tracked IPs in tests. Sufficient for unit and integration tests;
not a deployment profile.

---

## 9. Conformance checklist

For an implementation to claim Bedrock Echo conformance:

- [ ] Parses the 14-byte header per PROTOCOL.md §2.
- [ ] Implements all 7 wire msg_types per PROTOCOL.md §3-4.
- [ ] Passes all test vectors in `testvectors/` byte-exactly
      (encode and decode roundtrip).
- [ ] Strict (src_ip, sender_id) match for steady-state lookups; no
      sender_id-only fallback, no HEARTBEAT new-node-join scan
      (§1.2, §1.4).
- [ ] Implements collision resolution via AEAD trial decryption when
      multiple entries share sender_id (§1.2).
- [ ] Generates and rotates `witness_cookie_secret` per PROTOCOL.md
      §11.2 (current + previous, 1-hour rotation).
- [ ] Validates the cookie on every BOOTSTRAP before AEAD decryption
      (§2.1).
- [ ] Pads DISCOVER to 62 B and accepts DISCOVER == 62 B (rejects
      lengths < 62, MAY check zero-padding).
- [ ] Enforces per-sender monotonic timestamp_ms (§4.1).
- [ ] Supports full 0..1152 B payload range (no capping to smaller
      sizes).
- [ ] Silently drops malformed, expired, or unverifiable packets
      (no error replies).
- [ ] Rate-limits per-IP token bucket (§5.1) and INIT 1/sec/IP.
- [ ] Implements age-out tiers (§5).
- [ ] If applicable (embedded/memory-constrained): implements
      block allocator + defrag per §3.2-3.3.
