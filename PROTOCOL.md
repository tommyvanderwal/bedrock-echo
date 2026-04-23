# Bedrock Echo Protocol — v0.002 (DRAFT)

**Status:** Draft for review. Once frozen, this spec is the contract between
all implementations. Changes require a version bump.

**Transport:** UDP, default port 7337 (configurable; not part of the protocol).
**One message = one UDP datagram.** Every message fits in a single datagram
under typical Ethernet MTU (≤1400 B). The protocol has no fragmentation and no
streaming; if a deployment needs more, that's a v0.2 conversation.

---

## 1. Design principles

1. **Every multi-byte integer is big-endian (network byte order).** No exceptions.
2. **No variable-length integers, no TLV, no optional fields.** Every offset is
   known from `msg_type` alone.
3. **No strings on the wire.** Identifiers are fixed-size byte arrays.
4. **No floats.** Timestamps are `int64` ms since Unix epoch; durations are
   `uint32` ms or `uint32` seconds.
5. **Every datagram ≤ 1400 bytes** — under Ethernet UDP MTU with margin. No IP
   fragmentation ever.
6. **Strict parsing.** Wrong magic, flags, length, HMAC, or AEAD tag = silent
   drop. No lenient mode, no partial parse, no "ignore unknown fields".
7. **Version is in the magic.** `BEW1` = v1. v2 will use `BEW2` and dual-stack
   impls MUST dispatch by the first 4 bytes.
8. **Crypto primitives are the common-denominator set:** X25519, HKDF-SHA256,
   HMAC-SHA256, ChaCha20-Poly1305. Available in every major language's standard
   crypto lib and on ESP32 mbedTLS. **No Ed25519 in v1** — possession of the
   X25519 private key proved by successful ECDH is the witness's identity.
9. **No cluster_id on the wire.** The cluster is defined by its shared HMAC
   key. Witness looks up `sender_id → cluster` once per node and caches.
10. **No fragmentation.** STATUS comes in two flavours — a compact list (all
    nodes, 64 fit easily) or a single-peer detail (full 128 B payload). Node
    picks which reply it wants per heartbeat.

---

## 2. Common packet header

Every Bedrock Echo packet starts with the same **32-byte header**:

```
Offset  Size  Name          Type    Description
────────────────────────────────────────────────────────────────────────────
0       4     magic         bytes   "BEW1"  = 0x42 0x45 0x57 0x31
4       1     msg_type      u8      see §3
5       1     flags         u8      reserved, MUST be 0x00 in v1
6       8     sender_id     bytes   64-bit stable node identifier
                                    (0x0000000000000000 is reserved/invalid
                                    for node senders; the witness MAY use it
                                    as its own sender_id in replies)
14      8     sequence      u64     monotonic per (sender_id, receiver)
22      8     timestamp_ms  i64     ms since Unix epoch, advisory
30      2     payload_len   u16     length of the payload section
────────────────────────────────────────────────────────────────────────────
Total header: 32 bytes
```

After the header comes the **payload** of length `payload_len`, and after the
payload comes the **trailer** (HMAC tag or nothing, per message type).

Every implementation MUST reject (silently drop) any packet where:
- total UDP length < 32 (can't even hold the header)
- `magic` ≠ `"BEW1"`
- `flags` ≠ `0x00`
- total UDP length ≠ `32 + payload_len + trailer_len(msg_type)`
- `sender_id == 0x0000000000000000` in a message from a node
- total UDP length > 1400 (MTU cap)

---

## 3. Message type table

| Code   | Name              | Direction            | Trailer            | Total size           |
|--------|-------------------|----------------------|--------------------|----------------------|
| `0x01` | HEARTBEAT         | node → witness       | HMAC-SHA256 (32 B) | 32 + payload_len + 32 |
| `0x02` | STATUS_LIST       | witness → node       | HMAC-SHA256 (32 B) | 32 + payload_len + 32 |
| `0x03` | STATUS_DETAIL     | witness → node       | HMAC-SHA256 (32 B) | 32 + payload_len + 32 |
| `0x10` | UNKNOWN_SOURCE    | witness → node       | none               | 32 + 0                |
| `0x20` | BOOTSTRAP         | node → witness       | none (AEAD inline) | 32 + payload_len      |
| `0x21` | BOOTSTRAP_ACK     | witness → node       | HMAC-SHA256 (32 B) | 32 + payload_len + 32 |

Any other `msg_type`: silently drop.

---

## 4. Message payloads

### 4.1 HEARTBEAT (`0x01`) — node → witness

Every heartbeat tells the witness "here's my current state" and asks one of two
questions:

- `query_target_id == 0` → reply **STATUS_LIST** (compact topology of the cluster)
- `query_target_id != 0` → reply **STATUS_DETAIL** (full state of that one peer)

Payload structure:

```
Offset  Size  Name              Type    Description
─────────────────────────────────────────────────────────────────────
0       8     query_target_id   bytes   peer's sender_id, or 0 for list
8       N     own_payload       bytes   0..128 bytes, opaque to witness
```

Constraints:
- `payload_len` ∈ `[8, 136]` (at minimum the 8-byte query field; at most plus
  128 B of own_payload).

The `own_payload` is stored verbatim by the witness and served to peers when
they request STATUS_DETAIL for this sender_id.

Trailer: 32 bytes HMAC-SHA256 over `header || payload`, key = cluster_key.

### 4.2 STATUS_LIST (`0x02`) — witness → node

Reply to a HEARTBEAT with `query_target_id == 0`. Compact topology snapshot of
the whole cluster — IDs and IPs and ages only, no per-node state payloads.
Always fits in one datagram for the max 64-node witness capacity.

Payload structure:

```
Offset  Size  Name                 Type    Description
──────────────────────────────────────────────────────────────────
0       8     witness_uptime_ms    u64     ms since witness booted
8       1     num_entries          u8      0..64
9       1     reserved             u8      MUST be 0x00
10      ...   node entries, each 16 bytes:
              Offset  Size  Name               Description
              ────────────────────────────────────────────────────
              0       8     peer_sender_id     the peer's sender_id
              8       4     peer_ipv4          IPv4 (big-endian)
              12      4     last_seen_seconds  u32 s since last heartbeat
```

Constraints:
- v0.001 is **IPv4 only**. An IPv6 variant is reserved for v0.2 (new
  `msg_type` or a future `BEW2`).
- Max payload: `10 + 64 × 16 = 1034` bytes. Full packet: `32 + 1034 + 32 = 1098`.
  Under 1400. No fragmentation even at full 64-node witness capacity.
- Entries are ordered by `last_seen_seconds` ascending (most-recently-heard
  first). Deterministic ordering aids testability.
- The requesting node's own entry, if present, is included.

Trailer: 32 bytes HMAC-SHA256 over `header || payload`, key = cluster_key.

### 4.3 STATUS_DETAIL (`0x03`) — witness → node

Reply to a HEARTBEAT with `query_target_id != 0`. Returns the full stored
state of a single peer. This is the common-case query in a 2- or 3-node
cluster: each node heartbeats "here's me, give me my peer's full payload" and
gets back exactly one peer's `own_payload`.

Payload structure (when peer is found, `status == 0`):

```
Offset  Size  Name                 Type    Description
──────────────────────────────────────────────────────────────────
0       8     witness_uptime_ms    u64
8       8     target_sender_id     bytes   echo of the query
16      1     status               u8      0x00 = found, 0x01 = not found
17      1     reserved             u8      MUST be 0x00
18      4     peer_ipv4            u32     big-endian IPv4
22      4     last_seen_seconds    u32
26      1     peer_payload_len     u8      0..128
27      N     peer_payload         bytes   the peer's last own_payload
```

If `status == 0x01` (not found): fields at offsets 18.. are omitted;
`payload_len` is exactly `18`:

```
Offset  Size  Name                 Description
────────────────────────────────────────────────────────
0       8     witness_uptime_ms
8       8     target_sender_id     echo of the query
16      1     status               0x01
17      1     reserved             0x00
```

Constraints:
- `payload_len` ∈ `[18, 155]` (18 for not-found; 27 for found+empty payload;
  155 for found + 128 B payload).

Trailer: 32 bytes HMAC-SHA256 over `header || payload`, key = cluster_key.

### 4.4 UNKNOWN_SOURCE (`0x10`) — witness → node (unauthenticated)

Sent when the witness receives a HEARTBEAT from a `sender_id` it does not
know, or from a known `sender_id` whose HMAC fails verification against all
cluster keys. Signals "please bootstrap (or re-bootstrap)".

Payload: empty (`payload_len == 0`).

No trailer (the witness doesn't have a shared key to HMAC with, and doesn't
know which cluster the sender thinks it's in).

**Rate-limited:** at most 1 UNKNOWN_SOURCE per source IP per second. Excess:
silently drop.

On receipt, a node that knows the witness's X25519 public key SHOULD initiate
a BOOTSTRAP. A node with no provisioned witness pubkey MUST ignore this
message (an on-path attacker can spoof it).

### 4.5 BOOTSTRAP (`0x20`) — node → witness

Establishes a cluster on the witness by delivering a fresh cluster_key under
X25519-ephemeral ECDH to the witness's published X25519 public key.

Payload structure (on the wire, already encrypted):

```
Offset  Size  Name         Description
────────────────────────────────────────────────────────
0       32    eph_pubkey   ephemeral X25519 public key
32      C     ciphertext   ChaCha20-Poly1305 output: enc(plaintext) || tag
                           C = plaintext_len + 16
```

Plaintext (before encryption):

```
Offset  Size  Name          Description
──────────────────────────────────────────────────────────
0       32    cluster_key   random 32-byte HMAC-SHA256 key
32      N     init_payload  opaque, 0..96 bytes
                            — same role as HEARTBEAT own_payload
```

Constraints:
- `plaintext_len = payload_len - 32 - 16 = payload_len - 48`
- `plaintext_len` ∈ `[32, 128]`
- Therefore `payload_len` ∈ `[80, 176]`
- Total packet: `32 + payload_len` ∈ `[112, 208]`

Crypto:
```
shared_secret = X25519(eph_privkey, witness_x25519_pubkey)      # 32 bytes
derived_key   = HKDF-SHA256(ikm = shared_secret,
                            salt = 32 zero bytes,
                            info = b"bedrock-echo v1 bootstrap",
                            length = 32)                         # 32 bytes
nonce         = 12 zero bytes
aad           = packet header (bytes [0..32])
ciphertext    = ChaCha20-Poly1305-Encrypt(derived_key, nonce, aad, plaintext)
```

Zero nonce is safe here because `derived_key` is single-use — it depends on
`eph_privkey` which is freshly generated per BOOTSTRAP packet.

No trailer: integrity of the whole packet (header as AAD, plaintext as
AEAD-encrypted) is provided by the Poly1305 tag already inside `ciphertext`.

### 4.6 BOOTSTRAP_ACK (`0x21`) — witness → node

Reply to a successful BOOTSTRAP. Authenticated with the just-established
cluster_key.

Payload structure:

```
Offset  Size  Name                  Description
────────────────────────────────────────────────────
0       1     status                see below
1       8     witness_uptime_ms     u64
```

`payload_len` is exactly 9.

`status` values:
- `0x00` = new cluster installed
- `0x01` = re-bootstrap, same cluster_key (idempotent confirmation)

If the witness sees a BOOTSTRAP from a sender_id already in its table and the
decrypted cluster_key is **different** from the one on file: silently drop.
Do NOT send a "wrong key" error — that leaks the existence of a cluster to an
attacker.

Trailer: 32 bytes HMAC-SHA256 over `header || payload`, key = cluster_key.

---

## 5. Cryptography

### 5.1 Witness key

On first boot the witness generates and persists to flash **one** X25519
keypair:

- `witness_x25519_priv` (32 bytes, never leaves the device)
- `witness_x25519_pub`  (32 bytes, displayed on boot console)

The admin configures `witness_x25519_pub` + witness IP on each cluster node
out-of-band. This is the only manual config step in the protocol lifecycle.

### 5.2 Cluster key

A 32-byte random secret generated by the first node that bootstraps each
cluster. Transmitted to the witness only once, inside a BOOTSTRAP. All
subsequent packets in both directions are HMAC'd with it.

Nodes of the same cluster share the same cluster_key (distributed
out-of-band by cluster operator — a config file or provisioning system).
Cluster key distribution among nodes is out of scope for the protocol.

### 5.3 HMAC coverage

For HEARTBEAT, STATUS_LIST, STATUS_DETAIL, BOOTSTRAP_ACK:

```
HMAC-SHA256(key = cluster_key,
            data = packet_bytes[0 .. 32 + payload_len])
```

The trailer covers the entire packet **except the trailer itself**.

Verification: recompute HMAC over the same range, compare in constant time.
Mismatch: silently drop.

### 5.4 No key rotation in v1

Cluster key set at bootstrap, remains until re-bootstrap. v0.2 may add explicit
rotation.

---

## 6. Sequence numbers and replay protection

`sequence` is a per-(sender_id → receiver) monotonic 64-bit counter. The
witness tracks per-sender `last_rx_sequence`; packets with `sequence ≤
last_rx_sequence` are silently dropped. Witness also tracks `last_tx_sequence`
per sender and strictly increments for replies.

**Recommended sender implementation:**
```
next_sequence = max(current_wall_time_ms_since_epoch, last_sent_sequence + 1)
```

Gives every node a fresh, monotonic counter across reboots without state
persistence. Small backwards NTP steps are absorbed by the `+ 1` rule.

On successful bootstrap, the witness resets its tracked last_rx/last_tx for
that sender to 0, allowing the first real HEARTBEAT to start from any value
> 0.

---

## 7. Timestamps

`timestamp_ms` is advisory. It does NOT determine acceptance. Applications MAY
use it to detect clock skew. A witness with no RTC (ESP32 without NTP) SHOULD
set `timestamp_ms = 0`. Receivers MUST accept 0 without special handling.

---

## 8. Witness state model (RAM-only)

The witness keeps a flat table of up to **64 node entries** across up to
**32 distinct clusters**. Each entry:

```
sender_id         [u8; 8]     primary lookup key
sender_ipv4       [u8; 4]     learned from UDP source
cluster_slot      u8          index into the cluster table
last_rx_ms        u64         witness-local monotonic ms of last heartbeat
last_rx_sequence  u64
last_tx_sequence  u64
payload_len       u8          0..128
payload           [u8; 128]
```

Per entry: ~160 bytes. 64 entries: ~10 KB. Fits any ESP32 with room to spare.

**Cluster table** (up to 32 entries):

```
cluster_slot      u8          local index
cluster_key       [u8; 32]
bootstrapped_ms   u64         witness-local monotonic
num_nodes         u8
```

~50 bytes × 32 = ~1.6 KB.

**Per-source-IP rate-limiter** (up to 128 tracked IPs):

```
ipv4              [u8; 4]
tokens            u8
last_refill_ms    u32
```

~10 bytes × 128 = ~1.3 KB.

**Total witness RAM footprint:** ~13 KB. Even conservative ESP32 builds have
tens of KB available.

Everything lost on reboot. No flash writes after the first-boot key
generation.

---

## 9. Witness lookup logic

On incoming packet (after header validation):

```
1. If msg_type == 0x20 (BOOTSTRAP):
     decrypt, match sender_id against node table:
       - new sender_id: install node + cluster if slots available
       - existing sender_id with matching cluster_key: idempotent re-bootstrap
       - existing sender_id with different cluster_key: silently drop
     reply BOOTSTRAP_ACK.

2. Else:
     look up node entry by sender_id (linear scan or hash — 64 entries).
     if none found: reply UNKNOWN_SOURCE (rate-limited).
     verify HMAC against entry's cluster_key.
       - mismatch: reply UNKNOWN_SOURCE (rate-limited).
       - match: update sender_ipv4 if changed, last_rx_ms, last_rx_sequence,
                payload (for HEARTBEAT).
     dispatch by msg_type:
       - HEARTBEAT with query_target_id == 0: reply STATUS_LIST
       - HEARTBEAT with query_target_id != 0: reply STATUS_DETAIL
```

No "try all cluster keys" scan is required. First-time sender_id = UNKNOWN_SOURCE
→ node re-bootstraps → entry created → from then on O(1) by sender_id.

---

## 10. Dynamic timeouts (age-out)

| Node table fill        | Age-out after |
|------------------------|---------------|
| < 25% (< 16 entries)   | 72 hours      |
| 25% – 75%              | 1 hour        |
| > 75% (> 48 entries)   | 5 minutes     |

Age-out: delete the node entry. If the cluster has no remaining nodes,
also delete the cluster entry.

The `last_seen_seconds` field in STATUS replies is `u32` so values up to ~136
years represent cleanly; the 72-hour cap just means entries disappear rather
than showing huge numbers.

---

## 11. Rate limiting

Per source IP, the witness enforces a token bucket: 10 packets/second, burst
20. Over the limit: silently dropped. UNKNOWN_SOURCE replies additionally
rate-limited to 1/second/source IP.

Tracked IPs capped at 128; when full, evict oldest. This is anti-DDoS hygiene
for small LANs. Upstream firewalling is expected in production.

---

## 12. Silent-drop rules (summary)

Silently drop any packet that:

1. Has wrong magic, wrong flags, wrong msg_type, or declared length doesn't
   match UDP length.
2. Exceeds MTU cap (1400 B).
3. Has `sender_id == 0` in a node→witness message.
4. Fails HMAC (for HMAC'd types).
5. Fails AEAD (for BOOTSTRAP).
6. Has `sequence ≤ last_rx_sequence` for its sender_id.
7. Exceeds rate limit for its source IP.
8. Has `payload_len` outside the per-msg_type range.
9. BOOTSTRAP with sender_id already in table and different cluster_key.

The only "error" response defined is UNKNOWN_SOURCE (§4.4).

---

## 13. Canonical flows

### 13.1 Happy path — DRBD 2-node cluster

Steady state: each node heartbeats every 3 s, asking for the peer's detail.

```
nodeA (sender_id = A)                             witness              nodeB
  │  HEARTBEAT(query=B, own_payload=drbd_state_A) │                       │
  │─────────────────────────────────────────────►│                       │
  │                                               │ HMAC ok, store        │
  │  STATUS_DETAIL(target=B, ipv4, ls_s, B's pl)  │                       │
  │◄─────────────────────────────────────────────│                       │
  │                                                                       │
  │                                               │  HEARTBEAT(query=A)   │
  │                                               │◄──────────────────────│
  │                                               │   STATUS_DETAIL(A)    │
  │                                               │──────────────────────►│
```

Neither node ever asks for the full LIST in steady state; STATUS_DETAIL is
enough. Periodic LIST queries (every few minutes) confirm no surprise nodes
have appeared.

### 13.2 Cold bootstrap

```
admin: configure nodes with witness_x25519_pub + IP + cluster_key

nodeA                                             witness (fresh boot)
  │  HEARTBEAT(query=B, ...)                       │
  │─────────────────────────────────────────────► │ sender_id unknown
  │  UNKNOWN_SOURCE                                │
  │◄──────────────────────────────────────────────│
  │                                                │
  │  BOOTSTRAP(eph_pk, enc(cluster_key + init))    │
  │─────────────────────────────────────────────► │ decrypt, install
  │  BOOTSTRAP_ACK(status=0x00)                    │
  │◄──────────────────────────────────────────────│
  │                                                │
  │  HEARTBEAT(query=B, ...)                       │
  │─────────────────────────────────────────────► │
  │  STATUS_DETAIL(target=B, status=not_found)     │   (B hasn't joined yet)
  │◄──────────────────────────────────────────────│
```

Later, nodeB runs the same flow.

### 13.3 Witness reboot

Indistinguishable from cold bootstrap from the node's side. Both nodes start
getting UNKNOWN_SOURCE, both re-bootstrap, witness state rebuilt within a few
heartbeat rounds.

### 13.4 Node IP change

Node's DHCP lease changes from 192.168.2.10 → 192.168.2.20. Next HEARTBEAT
arrives from the new IP. Witness looks up by `sender_id` (unchanged), HMAC
verifies, updates `sender_ipv4` field. No re-bootstrap. Peers see the new IP
in their next STATUS_LIST.

---

## 14. Security notes (v0.001)

**In scope:**
- Forgery prevention (HMAC-SHA256 on all authenticated traffic).
- Confidentiality + integrity of cluster-key delivery (ChaCha20-Poly1305 AEAD
  over X25519 ECDH).
- Replay prevention (sequence numbers).
- Basic DDoS resistance (per-IP token bucket, silent drop on failure).

**Out of scope / known weaknesses:**
- On-path attacker during BOOTSTRAP cannot decrypt but can race a bogus one to
  an unknown witness. Witness accepts the first BOOTSTRAP for a sender_id;
  later ones with different cluster_keys are silently dropped. Operational
  fix: ensure each node provisions a unique cluster_key copy.
- Cluster key is a single shared secret per cluster. Compromise of any node
  leaks all other nodes' HMAC'd traffic. Acceptable for LAN.
- No forward secrecy for steady-state traffic. Acceptable: witness has no
  confidential data; it stores short-lived state hints.
- No post-quantum primitives.
- No signed witness statements. If a v0.2 use case needs
  third-party-verifiable witness output (audit logs, dashboards), add Ed25519
  and a new msg_type with a signature trailer.

---

## 15. Test vectors

Test vectors live under `testvectors/` as pairs:

- `NN_msgtype_description.in.json` — all inputs (keys, payload, sequence,
  timestamp, any randomness like eph_privkey)
- `NN_msgtype_description.out.bin`  — the exact bytes on the wire

v0.001 ships these vectors:

| Vector                                    | Purpose                                 |
|-------------------------------------------|-----------------------------------------|
| `01_heartbeat_list_query.{json,bin}`      | HEARTBEAT with query=0 (request list)   |
| `02_heartbeat_detail_query.{json,bin}`    | HEARTBEAT with query=peer (request detail) |
| `03_status_list_two_nodes.{json,bin}`     | STATUS_LIST reply                       |
| `04_status_detail_found.{json,bin}`       | STATUS_DETAIL with peer found           |
| `05_status_detail_not_found.{json,bin}`   | STATUS_DETAIL with peer not found       |
| `06_unknown_source.{json,bin}`            | UNKNOWN_SOURCE reply                    |
| `07_bootstrap.{json,bin}`                 | BOOTSTRAP (fixed eph key + plaintext)   |
| `08_bootstrap_ack_new.{json,bin}`         | BOOTSTRAP_ACK status=0x00               |
| `09_bootstrap_ack_rebootstrap.{json,bin}` | BOOTSTRAP_ACK status=0x01               |

Keys and randoms in the JSON inputs are FIXED so the `.out.bin` is
byte-reproducible across implementations.

Both Python and Rust test suites MUST pass:
- `encode(inputs) == out.bin` byte-exact
- `decode(out.bin) → inputs` round-trip

---

## 16. Recommended sender_id construction

Not enforced by protocol, but recommended for real deployments:

```
sender_id = SHA256(MAC_address || hostname)[0..8]
```

Stable across reboots, globally unique in practice, no coordination needed.
For the KVM pilot: `SHA256(vNIC_MAC || VM_name)[0..8]`.

---

## 17. Versioning and compatibility

- The `magic` field is the sole version indicator. `BEW1` = v1.
- Future versions use a different magic (`BEW2`, `BEW3`, ...).
- A v2 impl that wants to interop with v1 MUST implement both magics and
  dispatch by the first 4 bytes.
- No negotiation. Sender picks a version; receiver either speaks it or
  silently drops.

---

## 18. v0.2 roadmap (not this version)

- IPv6 node addresses (new STATUS_LIST entry format or new `msg_type`).
- 3-witness / 5-witness majority mode (witnesses unchanged, node quorum logic
  extended).
- Explicit `ROTATE_KEY` message for cluster-key rotation without full
  re-bootstrap.
- Ed25519-signed witness replies for third-party verifiability.
- Multicast witness discovery (so nodes don't need IP configured).

---
