# Bedrock Echo Protocol — v1.0

**Status:** Frozen. Once implementations start shipping on firmware that goes
into boxes we will never touch again, changes to this spec are forbidden. A
genuinely different protocol ships on a different UDP port, not a new version.

**Transport:** UDP, default port **12321** (configurable by deployment; the
port number is not part of the protocol itself).
**One message = one UDP datagram.** Every message fits in a single datagram
under typical Ethernet MTU (≤ 1400 B). The protocol has no fragmentation and
no streaming; a deployment needing more uses a different UDP port for a
different protocol.

---

## 1. Design principles

1. **Every multi-byte integer is big-endian (network byte order).** No exceptions.
2. **No variable-length integers, no TLV, no optional wire fields.** Every offset
   is known from `msg_type` alone (combined with inline length fields where
   variable-length payloads are explicitly carried).
3. **No strings on the wire.** Identifiers are fixed-size bytes/integers.
4. **No floats.** Timestamps are `int64` ms since Unix epoch; durations are
   `uint32` ms or `uint32` seconds depending on the field.
5. **Every datagram ≤ 1400 bytes.** Below Ethernet UDP MTU with margin. No IP
   fragmentation ever.
6. **Strict parsing.** Wrong magic, bad length, bad AEAD tag = silent drop. No
   lenient mode, no partial parse, no "ignore unknown fields" except where
   explicitly defined as forward-compat reserved bits in a status byte.
7. **No protocol version field.** The magic is `Echo`, forever. If a genuinely
   different protocol is needed later, it ships on a different UDP port — not
   as a version bump over this one. This avoids the "old firmware in the wild
   breaking when we upgrade" failure mode.
8. **`msg_type` is the primary extension point.** 256 values, 7 used today.
   Unknown `msg_type` → silent drop, so old implementations forward-compat
   by design.
9. **Crypto primitives are the common-denominator set:** X25519, HKDF-SHA256,
   ChaCha20-Poly1305. Available in every major language's standard crypto
   library and on ESP32 mbedTLS. **No HMAC-SHA256, no Ed25519** — authenticated
   integrity is provided by AEAD's Poly1305 tag everywhere a shared key
   exists.
10. **No `cluster_id` on the wire.** The cluster is defined by its shared
    `cluster_key`. The witness disambiguates which cluster an authenticated
    packet belongs to via AEAD trial decryption against candidate cluster_keys
    (typically narrowed to a single candidate by the source IP filter).
11. **`sender_id` is 1 byte, cluster-scoped.** Multiple clusters served by the
    same witness can use overlapping sender_ids; the witness resolves
    collisions via AEAD verification.
12. **Authenticated payloads are encrypted.** All authenticated message types
    use AEAD (ChaCha20-Poly1305) to provide both confidentiality and
    integrity. Only DISCOVER and UNKNOWN_SOURCE are unauthenticated — those
    are bootstrap-discovery messages and have no shared key.

---

## 2. Common packet header

Every Bedrock Echo packet starts with the same **14-byte header**:

```
Offset  Size  Name          Type    Description
─────────────────────────────────────────────────────────────────────
0       4     magic         bytes   "Echo" = 0x45 0x63 0x68 0x6f
4       1     msg_type      u8      see §3
5       1     sender_id     u8      0x00..0xFE for nodes (cluster-scoped)
                                    0xFF reserved for the witness
6       8     timestamp_ms  i64     ms since Unix epoch, big-endian
                                    Strict-monotonic per sender
                                    (see §6)
─────────────────────────────────────────────────────────────────────
Total: 14 bytes
```

After the header comes the **message-specific payload**, then for authenticated
messages a **16-byte Poly1305 tag** as the AEAD trailer.

Every implementation MUST silently drop any packet where:
- total UDP length < 14 (can't even hold the header)
- `magic` ≠ `"Echo"`
- total UDP length > 1400 (MTU cap)
- `msg_type` is unknown
- the structure for the given `msg_type` doesn't match the UDP length
- the AEAD tag fails verification (for authenticated types)

---

## 3. Message type table

| Code   | Name              | Direction        | Auth     | Total size            |
|--------|-------------------|------------------|----------|-----------------------|
| `0x01` | HEARTBEAT         | node → witness   | AEAD     | 32 + 32N B            |
| `0x02` | STATUS_LIST       | witness → node   | AEAD     | 35 + 5N B             |
| `0x03` | STATUS_DETAIL     | witness → node   | AEAD     | 36 (not found) / 44 + 32N B (found) |
| `0x04` | DISCOVER          | node → witness   | none     | 14 B                  |
| `0x10` | UNKNOWN_SOURCE    | witness → node   | none     | 46 B                  |
| `0x20` | BOOTSTRAP         | node → witness   | AEAD-DH  | 94 B                  |
| `0x21` | BOOTSTRAP_ACK     | witness → node   | AEAD     | 35 B                  |

Where `N` indicates a payload-specific block count or entry count, defined
per message below.

Any other `msg_type`: silently drop.

---

## 4. Cryptographic constructions

### 4.1 Variable-length payload encoding

Three message types carry an opaque variable-length application payload:
HEARTBEAT (`own_payload`), STATUS_DETAIL (`peer_payload`), BOOTSTRAP
(`init_payload` is removed in v1; see §4.5).

These payloads are encoded as **N blocks of 32 bytes each**, where N is
declared by an inline u8 count field. Valid range: `N ∈ [0, 36]`. A value
N = 36 yields a 1152-byte payload (1024 bytes of "data" plus 128 bytes of
"app metadata," or any other split the application chooses).

Any value `N > 36` is rejected (silent drop).

Implementation note: the 32-byte block granularity matches the witness's
preferred internal storage allocator (see witness-implementation guide).
The block count and the start of `*_payload` together form a 16-byte
boundary in the on-wire layout for HEARTBEAT, naturally alignment-friendly.

### 4.2 AEAD construction for cluster_key-protected messages

Used for: HEARTBEAT, STATUS_LIST, STATUS_DETAIL, BOOTSTRAP_ACK.

```
key       = cluster_key                       (32 B, shared between the
                                               cluster's nodes and the
                                               witness)
nonce     = sender_id                         (1 B)
         || 0x00 0x00 0x00                    (3 B, fixed)
         || timestamp_ms (BE)                 (8 B, from header)
                                              = 12 B
aad       = packet_bytes[0 .. 14]             (the 14-byte header)
plaintext = message-specific payload (see §5)
ct, tag   = ChaCha20-Poly1305-Encrypt(key, nonce, aad, plaintext)
```

The ciphertext has the same length as the plaintext. The 16-byte Poly1305
tag is appended after the ciphertext.

The header (sender_id + timestamp_ms) ensures the (key, nonce) pair is
unique per packet — see §6.

### 4.3 AEAD construction for BOOTSTRAP

BOOTSTRAP delivers the cluster_key to the witness, so cluster_key cannot be
the AEAD key. Instead, an ephemeral X25519 keypair is used to derive a
per-packet AEAD key.

```
Sender (node) computes:
  eph_secret  = 32 random bytes (X25519-clamped)
  eph_pubkey  = X25519_base_multiply(eph_secret)
  shared      = X25519(eph_secret, witness_pubkey)
  aead_key    = HKDF-SHA256(
                  ikm  = shared,
                  salt = [0x00] × 32,
                  info = b"bedrock-echo bootstrap",
                  L    = 32
                )
  nonce       = [0x00] × 12   (safe: aead_key is unique per packet)
  aad         = packet_bytes[0 .. 14]
  plaintext   = cluster_key  (32 B)
  ct, tag     = ChaCha20-Poly1305-Encrypt(aead_key, nonce, aad, plaintext)
  
After encryption the sender MUST destroy eph_secret.
```

The receiver (witness) computes the **same** `shared` value:

```
shared    = X25519(witness_secret, eph_pubkey)
            (mathematically identical to the node's shared by the symmetry
            of X25519: mix(my_priv, your_pub) == mix(your_priv, my_pub))
aead_key  = HKDF-SHA256(...)   (same inputs)
            ChaCha20-Poly1305-Decrypt(...)
```

**MUST: senders generate a fresh ephemeral X25519 keypair for each
BOOTSTRAP and discard the private key after encryption.** Reuse causes
encryption-key reuse with zero nonce, leaking plaintext XOR across messages.

### 4.4 Cryptographic guarantees

For AEAD-encrypted messages (every message type except DISCOVER and
UNKNOWN_SOURCE):

| Property | Status | Mechanism |
|---|---|---|
| Confidentiality of payload | ✓ | ChaCha20 stream cipher under per-cluster key |
| Integrity of payload + header | ✓ | Poly1305 tag covers ciphertext + AAD |
| Replay rejection | ✓ | Strict-monotonic timestamp_ms per sender (see §6) |
| Per-packet key/nonce freshness | ✓ | Nonce derived from unique (sender_id, timestamp_ms) |
| Cross-cluster privacy | ✓ | Separate cluster_keys per cluster; one cluster cannot decrypt another's traffic |

For BOOTSTRAP specifically (the cluster_key delivery operation):

| Property | Status | Mechanism |
|---|---|---|
| Confidentiality of cluster_key in transit | ✓ | Ephemeral-static X25519 ECDH; without `witness_secret` an attacker cannot derive `aead_key` |
| Integrity of the BOOTSTRAP packet | ✓ | Poly1305 over ciphertext + AAD |
| Per-packet key freshness | ✓ | Fresh ephemeral keypair; aead_key unique per packet |
| **Forward secrecy if witness_secret leaks later** | **✗** | Future leak of `witness_secret` allows decryption of captured BOOTSTRAPs. Mitigation: rotate witness keypair. |

Forward secrecy is not achievable in a single-message, static-recipient
construction. A v2 design with a multi-message handshake could provide it.

### 4.5 What is encrypted vs plaintext on the wire

```
Authenticated message format:
  [ 14 B header — plaintext, used as AAD ]
  [ N  B encrypted payload ]
  [ 16 B Poly1305 tag ]

Unauthenticated message format:
  [ 14 B header — plaintext ]
  [ N  B plaintext payload (if any) ]
```

The header is always plaintext. This is necessary so the receiver can:
- Identify the packet as Echo (via magic),
- Dispatch to the correct handler (via msg_type),
- Look up the right key by source IP and sender_id,
- Reconstruct the AEAD nonce.

Tampering with header bytes invalidates the Poly1305 tag (header is in AAD),
so the witness silently drops modified packets.

---

## 5. Message payloads

### 5.1 HEARTBEAT (`0x01`) — node → witness

Every heartbeat tells the witness "here's my current state" and asks one
of two questions:

- `query_target_id == 0xFF` → reply STATUS_LIST (compact cluster topology)
- `query_target_id ∈ [0x00, 0xFE]` → reply STATUS_DETAIL (full state of
  that one peer; may equal sender's own ID for self-query)

Plaintext layout (encrypted on the wire under cluster_key):

```
Offset  Size  Name                Type    Description
─────────────────────────────────────────────────────────────────────
0       1     query_target_id     u8      0xFF = LIST request,
                                          0x00..0xFE = DETAIL target
1       1     own_payload_blocks  u8      0..36 (rejects > 36)
2       32N   own_payload         bytes   N × 32 B opaque app state
─────────────────────────────────────────────────────────────────────
Total plaintext: 2 + 32N bytes
```

On the wire (with header and tag):

```
Total UDP size: 14 + (2 + 32N) + 16 = 32 + 32N bytes
  N=0  →   32 B
  N=4  →  160 B  (typical Raft / DRBD with signed state)
  N=36 → 1184 B  (max payload, 216 B MTU slack)
```

`own_payload` is stored verbatim by the witness and served to peers
when they request STATUS_DETAIL for this sender_id.

### 5.2 STATUS_LIST (`0x02`) — witness → node

Reply to a HEARTBEAT with `query_target_id == 0xFF`. Compact cluster
topology snapshot — IDs and ages only, no per-node application payloads.

Plaintext layout:

```
Offset  Size  Name                     Type    Description
─────────────────────────────────────────────────────────────────────
0       4     witness_uptime_seconds   u32     seconds since witness boot
4       1     num_entries              u8      0..128
                                               (NOT 255 — see cap below)
─── Entries (5 B × num_entries) ─────────────────────────────────────
5       1     entry[0].peer_sender_id  u8      peer's 1-byte ID
6       4     entry[0].last_seen_ms    u32     ms since witness received
                                               peer's last heartbeat,
                                               in cluster's frame
10  …   …     entry[1..N-1]                    same 5-B layout

Total plaintext: 5 + 5N bytes
```

On the wire:

```
Total UDP size: 14 + (5 + 5N) + 16 = 35 + 5N bytes
  N=0   →  35 B
  N=2   →  45 B  (typical DRBD pair: caller + 1 peer)
  N=7   →  70 B  (typical Raft 7-node)
  N=128 → 675 B  (cap, 725 B MTU slack)
```

**Cap: 128 entries.** Plenty for any realistic cluster (MongoDB caps voters
at 50; deployed Raft ≤ 20; Corosync ≤ 32). The cap exists to keep
`num_entries` u8-sized and to bound witness reply size.

**Ordering:** entries are sorted ascending by `last_seen_ms`
(most-recently-heard first). Deterministic ordering enables byte-exact
test vector reproduction.

**The requesting node's own entry IS included** in the list (with
`last_seen_ms` typically near zero, since the witness just received the
caller's heartbeat). This gives the caller a "ground-truth" view of its
own sender_id in the cluster and confirms the witness's processing of its
heartbeat.

**No `peer_ipv4` field.** The list is for membership and freshness only.
For a peer's IP and full state, use STATUS_DETAIL.

### 5.3 STATUS_DETAIL (`0x03`) — witness → node

Reply to a HEARTBEAT with `query_target_id ∈ [0x00, 0xFE]`. Returns the
full stored state of one peer, or signals "not found" if the witness has
no entry for that target in the caller's cluster.

**Self-query is allowed and useful.** A node MAY set
`query_target_id == its own sender_id`. The witness replies with that
node's own most-recently-stored state — essentially "here's what you
told me last." This enables the advertise-verify-act pattern in
Appendix A.

Plaintext layout:

```
Offset  Size  Name                     Type    Description
─────────────────────────────────────────────────────────────────────
0       4     witness_uptime_seconds   u32     seconds since witness boot
4       1     target_sender_id         u8      echo of the query target
5       1     status_and_blocks        u8      see below

Status_and_blocks byte:
  bit 7 (0x80):  0 = peer found, 1 = peer not found
  bit 6 (0x40):  reserved (v1 senders MUST set 0; v1 receivers
                 MUST ignore — forward-compat flag)
  bits 0-5 (0x3F):
    when bit 7 = 0 (found):     peer_payload block count (0..36)
    when bit 7 = 1 (not found): reserved future flags
                                (v1 senders MUST set 0;
                                 v1 receivers MUST ignore)

Permitted v1 byte values:
  0x00..0x24 (0..36)   — found, that many blocks of peer_payload follow
  0x25..0x3F           — invalid (silent drop)
  0x40..0x64           — bit-6 set (v2+ flag); v1 still extracts block
                         count via (B & 0x3F); silent drop if > 36
  0x65..0x7F           — invalid (silent drop)
  0x80..0xFF           — not found (any reason flags in bits 0-6)
```

If `status_and_blocks` indicates **found** (bit 7 = 0):

```
Offset  Size  Name                     Type    Description
─────────────────────────────────────────────────────────────────────
6       4     peer_ipv4                bytes   peer's IPv4, big-endian
10      4     peer_seen_ms_ago         u32     ms since witness received
                                               peer's last heartbeat
14      32N   peer_payload             bytes   N × 32 B (where N comes
                                               from status_and_blocks)
                                               16-byte aligned
─────────────────────────────────────────────────────────────────────
Total plaintext (found): 14 + 32N bytes
```

If `status_and_blocks` indicates **not found** (bit 7 = 1): no
additional fields; payload ends at offset 6.

```
Total plaintext (not found): 6 bytes
```

On the wire:

```
Total UDP size (found):     14 (header) + (14 + 32N) (ciphertext) + 16 (tag)
                          = 44 + 32N B
Total UDP size (not found): 14 (header) + 6 (ciphertext) + 16 (tag)
                          = 36 B

Found N=0   →   44 B  (peer exists but never advertised state)
Found N=4   →  172 B  (typical Raft 128 B state)
Found N=36  → 1196 B  (max, 204 B MTU slack)
Not found   →   36 B
```

### 5.4 DISCOVER (`0x04`) — node → witness

Unauthenticated probe. The node asks the witness to identify itself.
Used during operator-driven witness discovery (dashboard "add witnesses"
flow) and for monitoring / latency probing.

```
14 B header only. No payload, no trailer.
Total: 14 bytes.
```

The witness replies with **UNKNOWN_SOURCE (`0x10`)** — same as for
authenticated messages that fail HMAC verification. Reusing
UNKNOWN_SOURCE as the discovery reply means the protocol has one
"witness identifies itself" message type instead of two.

DISCOVER is unauthenticated by necessity (no cluster_key exists to
authenticate against during discovery). The reply is similarly
unauthenticated; nodes verify the witness's pubkey out-of-band (DNSSEC
TXT records, operator provisioning, or TOFU + human verification).

### 5.5 UNKNOWN_SOURCE (`0x10`) — witness → node

Sent when the witness receives a DISCOVER, OR when it receives an
authenticated message (HEARTBEAT, etc.) that fails AEAD verification
against any known cluster_key for the sender_id and source IP. Carries
the witness's X25519 public key so callers can verify it (against
DNS-published or operator-provisioned values).

```
Offset  Size  Name              Type    Description
─────────────────────────────────────────────────────────────────────
── Header (14 B, plaintext) ────────────────────────────────────────
0       4     magic             "Echo"
4       1     msg_type          0x10
5       1     sender_id         0xFF (witness)
6       8     timestamp_ms      witness's best-effort wall-clock ms;
                                MAY be 0 if no clock source available;
                                informational only — not authenticated

── Payload (32 B, plaintext) ───────────────────────────────────────
14      32    witness_pubkey    the witness's X25519 public key

── No trailer ──────────────────────────────────────────────────────
                                Unauthenticated; no AEAD/HMAC tag.
─────────────────────────────────────────────────────────────────────
Total: 46 bytes
```

**Rate-limited:** witnesses MUST send no more than 1 UNKNOWN_SOURCE per
source IP per second. Excess: silent drop.

**Node-side handling:**
- Nodes MUST verify `witness_pubkey` matches their configured/expected
  pubkey before initiating BOOTSTRAP.
- Nodes with no configured pubkey AND not in explicit discovery mode
  MUST ignore UNKNOWN_SOURCE (an attacker can spoof it).
- Nodes SHOULD rate-limit their own re-bootstrap response (e.g., no more
  than one BOOTSTRAP per 30 seconds in response to repeated
  UNKNOWN_SOURCE).

### 5.6 BOOTSTRAP (`0x20`) — node → witness

Establishes a cluster on the witness by delivering a freshly-generated
`cluster_key` under X25519 ephemeral-static ECDH to the witness's published
X25519 pubkey. Single-purpose: the only thing transmitted is `cluster_key`.

```
Offset  Size  Name                Type    Description
─────────────────────────────────────────────────────────────────────
── Header (14 B, plaintext, AAD) ───────────────────────────────────
0       4     magic               "Echo"
4       1     msg_type            0x20
5       1     sender_id           caller's chosen ID (0x00..0xFE)
6       8     timestamp_ms        caller's wall-clock ms; seeds the
                                  cluster's time offset on the witness
                                  for subsequent per-cluster timestamping

── Ephemeral pubkey (32 B, plaintext) ──────────────────────────────
14      32    eph_pubkey          freshly-generated X25519 public key.
                                  The matching private key MUST be
                                  destroyed by the sender after
                                  encryption.

── Encrypted cluster_key + tag (48 B) ──────────────────────────────
46      32    encrypted_          ciphertext of the 32-byte cluster_key,
              cluster_key         under aead_key derived from
                                  X25519(eph_secret, witness_pubkey)
                                  via HKDF-SHA256.
78      16    poly1305_tag        AEAD tag covering the ciphertext
                                  and the 14-byte header (AAD).
─────────────────────────────────────────────────────────────────────
Total: 94 bytes (fixed)
```

Crypto details: see §4.3.

**State at the witness on successful BOOTSTRAP** (full state machine in
the witness implementation guide; semantics summary):

- New `(sender_id, cluster_key)` pair → allocate new node entry (and new
  cluster entry if the cluster_key wasn't already present).
- Existing `(sender_id, cluster_key)` pair → idempotent re-bootstrap;
  status 0x01 in the ACK; per-cluster offset adapted forward (§6.2).
- Existing sender_id but different cluster_key → create a new node entry
  (collision-resolution semantics; old coexists and ages out).

In all success cases, the witness replies with BOOTSTRAP_ACK.

**Failure modes** (silent drop, no UNKNOWN_SOURCE reply):
- AEAD verification fails (wrong pubkey, tampering, stale capture).
- `eph_pubkey` is an X25519 invalid input that yields zero shared
  secret (RFC 7748 small-subgroup elements).
- Witness state allocation fails (block pool exhausted, node table full).

### 5.7 BOOTSTRAP_ACK (`0x21`) — witness → node

Authenticated confirmation that BOOTSTRAP succeeded. Encrypted under the
just-installed `cluster_key`; receiving and decrypting it confirms to
the node that the witness recovered the cluster_key correctly.

Plaintext layout:

```
Offset  Size  Name                     Type    Description
─────────────────────────────────────────────────────────────────────
0       1     status                   u8      bit 0:
                                                 0 = new entry created
                                                 1 = idempotent re-bootstrap
                                               bits 1-7 reserved
                                               (v1 senders MUST set 0;
                                                v1 receivers MUST ignore)
1       4     witness_uptime_seconds   u32     seconds since witness boot
                                               (used for reboot detection)
─────────────────────────────────────────────────────────────────────
Total plaintext: 5 bytes
```

On the wire:

```
14  header
 5  encrypted plaintext
16  Poly1305 tag
─────────────────────────
35 B fixed
```

---

## 6. Anti-replay and timing

### 6.1 Strict monotonic `timestamp_ms` per sender

Senders MUST derive `timestamp_ms` for each outgoing packet as:

```
next_ts = max(wall_clock_ms_since_epoch, last_sent_ts + 1)
```

This rule is **MUST-strict**, not SHOULD. Violating it has two consequences:

1. **Anti-replay breaks.** The receiver tracks `last_rx_timestamp` per
   sender; new packets must be strictly greater. A non-monotonic sender
   would have its later packets silently dropped.
2. **AEAD security breaks.** The nonce derivation includes `timestamp_ms`
   (see §4.2). Non-unique timestamps from the same sender produce nonce
   reuse with the same cluster_key — a catastrophic AEAD violation that
   leaks plaintext XOR.

Both clients and the witness apply this rule symmetrically to their own
outgoing messages. The witness's monotonic counter is **per-cluster**:
each cluster has its own `last_tx_timestamp`. Implementations MAY use a
witness-global counter for simplicity at the cost of slightly faster
timestamp drift under load (no security or correctness consequence).

### 6.2 Per-cluster wall-clock derivation (witness without RTC)

A witness with no real-time clock (e.g., ESP32 without NTP) maintains a
per-cluster offset:

```
On first authenticated packet from cluster K (BOOTSTRAP or HEARTBEAT
that adds a node to an existing cluster):
  K.cluster_offset = packet.timestamp_ms - witness.uptime_ms
  
On every subsequent authenticated packet from cluster K:
  delta = packet.timestamp_ms - (witness.uptime_ms + K.cluster_offset)
  if delta > 0:
    K.cluster_offset += delta              # forward jump, accept
  elif delta > -1000:
    K.cluster_offset += max(delta, -10)    # backward, slow adapt (10ms/pkt cap)
  else:
    silent drop                             # too far behind cluster frame
  
Witness's outgoing timestamp_ms in cluster K's replies:
  ts_out = max(witness.uptime_ms + K.cluster_offset,
               K.last_tx_timestamp + 1)
  K.last_tx_timestamp = ts_out
```

A witness with NTP (e.g., Linux deployment) MAY skip the offset machinery
and use NTP wall-clock directly. The wire output is indistinguishable.

### 6.3 Receiver-side replay rejection

The witness tracks `last_rx_timestamp` per node entry. New packets must
satisfy `packet.timestamp_ms > entry.last_rx_timestamp` to be accepted;
otherwise silent drop.

On successful BOOTSTRAP (idempotent re-bootstrap or new entry),
`last_rx_timestamp` is set to **MAX(existing, packet.timestamp_ms)** —
preserving the monotonic invariant against replayed BOOTSTRAPs.

Implementations MAY accept a small in-window reorder tolerance (e.g.,
sliding window of last 16 accepted timestamps per sender) instead of
strict monotonic, to handle UDP reordering. This is a witness
implementation choice; senders MUST always be strictly monotonic.

---

## 7. Cluster_key

A 32-byte secret generated by the first node that bootstraps each cluster.
Transmitted to the witness exactly once, encrypted inside a BOOTSTRAP. All
subsequent authenticated traffic in both directions is AEAD-encrypted under
this key.

**Cluster_key distribution among nodes is out of scope for the protocol.**
The cluster operator distributes the same `cluster_key` to all nodes of
the cluster via the operator's own secure channel (configuration management
tool, vault, manual provisioning).

The witness stores cluster_keys in RAM only (no flash/disk persistence).
On witness reboot, all cluster state is lost; nodes re-bootstrap as part
of normal recovery.

**Cluster_key rotation** is operationally simple under the
collision-resolution model: the operator distributes a new cluster_key K2
to all nodes, who then BOOTSTRAP with K2. The witness creates new node
entries under K2 (alongside the existing entries under K1). Once all nodes
are using K2, the K1 entries age out naturally.

**No key rotation is built into the wire protocol** — it's entirely an
operational procedure on the cluster side.

---

## 8. Witness pubkey (X25519)

On first boot, the witness generates and persists to flash one X25519
keypair:

- `witness_secret` (32 bytes, never leaves the device, NVS-stored)
- `witness_pubkey` (32 bytes, distributed via DNS TXT records,
  operator config, or printed on the witness's serial console)

The pubkey distribution channel (DNSSEC, configuration management, manual)
is the trust root for the protocol. See the witness implementation guide
for recommended distribution patterns.

---

## 9. Witness state (RAM-only, no persistence except witness_secret)

The protocol does not specify witness state structures — those are
implementation choices. The witness implementation guide describes the
required behavior:

- Per-node entry: tracks `(cluster_id_handle, sender_ipv4, last_rx_ms,
  last_rx_timestamp, payload)`.
- Per-cluster entry: `(cluster_key, bootstrapped_ms, num_nodes,
  cluster_offset)`.
- Per-source-IP rate-limit table.

Sizing examples:
- ESP32 big profile: 512 nodes, 256 clusters, 36 KB block pool for
  payload storage. ~94 KB total state, ~86 KB heap.
- Linux hosted: ~30 K nodes, ~10 K clusters fit in <10 MB.

All state is lost on witness reboot; nodes re-bootstrap to recover.

---

## 10. Age-out (dynamic timeouts)

The witness reclaims state proactively under load. Two independent fill
metrics — node-table fill and payload-block-pool fill — drive a tier
selection:

| Tier (used = max of both fills) | Age-out timeout |
|---|---|
| 0–80% | 72 hours |
| 80–90% | 4 hours |
| > 90% | 5 minutes |

When a node's last-seen exceeds the active timeout, its entry (and its
payload blocks) are reclaimed. If a cluster has no remaining nodes after
this reclamation, the cluster entry is also dropped.

---

## 11. Rate limiting

Per source IP, the witness enforces a token bucket: 10 packets/second,
burst 20. Over the limit: silently dropped.

UNKNOWN_SOURCE replies have an additional per-source-IP rate limit of
1/second.

Tracked IPs are capped (e.g., 192 slots on ESP32 big profile); when the
table is full, the oldest entry is evicted. Anti-flood hygiene for small
LANs; production deployments are expected to firewall upstream of the
witness.

---

## 12. Silent-drop rules (summary)

The witness silently drops any packet that:

1. Has wrong magic, unknown msg_type, or UDP length inconsistent with the
   declared message structure.
2. Exceeds 1400 bytes.
3. Has `sender_id == 0xFF` in a node→witness message.
4. Fails AEAD tag verification (for AEAD-protected types).
5. Has `timestamp_ms` that fails per-sender monotonic check (for
   AEAD-protected types).
6. Exceeds the per-source-IP rate limit.
7. Has block-count or entry-count fields outside their valid range.
8. BOOTSTRAP with `eph_pubkey` that yields a zero shared secret
   (small-subgroup attack defense).
9. Witness state allocation fails (full).

The only "error reply" defined is UNKNOWN_SOURCE (§5.5), and only in the
specific cases noted there.

---

## 13. Canonical flows

### 13.1 Cold start of a new cluster

```
Operator provisions cluster_key K to all nodes via out-of-band channel
(cluster config, vault, etc.).

Node A boots:
  A → witness: HEARTBEAT (encrypted under K)
  witness has no entry for A, no cluster has K registered yet.
  witness → A: UNKNOWN_SOURCE (with witness_pubkey)
  A verifies witness_pubkey against expected.
  A → witness: BOOTSTRAP (cluster_key K, encrypted to witness_pubkey)
  witness installs cluster K, creates node entry for A.
  witness → A: BOOTSTRAP_ACK (status=0x00 new)
  A → witness: HEARTBEAT (encrypted under K, with own_payload)
  witness → A: STATUS_LIST (only A is in the list)

Node B boots later:
  B → witness: HEARTBEAT (encrypted under K)
  witness has entry for A (under K), no entry for B.
  Tries B's HMAC against K (via collision-resolution scan); succeeds.
  witness creates node entry for B under cluster K.
  witness → B: STATUS_LIST (A and B both in the list)
```

### 13.2 Steady state

```
Each node every ~2 seconds:
  Node N → witness: HEARTBEAT(query=peer_id, own_payload=current state)
  witness → Node N: STATUS_DETAIL(found, peer's last state)
```

A LIST query is sent periodically (every few minutes) to verify cluster
membership.

### 13.3 Witness reboot

```
Witness loses all state.

Each node's next HEARTBEAT → UNKNOWN_SOURCE (witness has no entries).
Each node BOOTSTRAPs.
First BOOTSTRAP installs the cluster; subsequent BOOTSTRAPs are
idempotent (status=0x01).
```

### 13.4 Node IP change

```
Node A's DHCP lease changes IP.
A → witness: HEARTBEAT from new IP, encrypted under K.
witness's IP-first lookup misses (new IP).
witness's sender_id-only fallback finds A's entry; AEAD verifies.
witness updates A's stored sender_ipv4.
Subsequent peers see A's new IP in their next STATUS_DETAIL queries.
```

### 13.5 Discovery flow (operator dashboard)

```
Dashboard has list of candidate witness addresses.
For each address:
  Dashboard → witness: DISCOVER
  witness → Dashboard: UNKNOWN_SOURCE (with witness_pubkey)
  Dashboard verifies pubkey against DNSSEC TXT or other trust source.
  Dashboard records (address, pubkey) for operator review.
```

---

## 14. Recommended sender_id construction

Not enforced by the protocol, but recommended for real deployments:

```
sender_id_byte = SHA256(MAC_address || hostname)[0]   # 1 byte
```

Stable across reboots, no operator coordination needed. Within a cluster,
collisions are an operator concern; cross-cluster collisions are
resolved by the witness via AEAD trial decryption.

For operators who prefer human-assigned IDs (e.g., "node-1, node-2,
node-3"): also fine. The protocol places no constraint beyond
`sender_id ≠ 0xFF`.

---

## 15. Test vectors

Test vectors live under `testvectors/` as pairs:

- `NN_msgtype_description.in.json` — all inputs (keys, payload, sender_id,
  timestamp, any randomness like eph_secret)
- `NN_msgtype_description.out.bin` — the exact bytes on the wire

v1 ships these vectors:

| Vector | Purpose |
|---|---|
| `01_heartbeat_list_query.{json,bin}`        | HEARTBEAT, query=0xFF, empty own_payload |
| `02_heartbeat_detail_query.{json,bin}`      | HEARTBEAT, query=peer, 4-block own_payload |
| `03_heartbeat_self_query.{json,bin}`        | HEARTBEAT, query=self, empty payload |
| `04_status_list_two_nodes.{json,bin}`       | STATUS_LIST, 2 entries |
| `05_status_list_empty.{json,bin}`           | STATUS_LIST, 0 entries |
| `06_status_detail_found.{json,bin}`         | STATUS_DETAIL with peer found, 4-block peer_payload |
| `07_status_detail_not_found.{json,bin}`     | STATUS_DETAIL not-found |
| `08_discover.{json,bin}`                    | DISCOVER |
| `09_unknown_source.{json,bin}`              | UNKNOWN_SOURCE with pubkey |
| `10_bootstrap.{json,bin}`                   | BOOTSTRAP (fixed eph_secret + cluster_key) |
| `11_bootstrap_ack_new.{json,bin}`           | BOOTSTRAP_ACK status=0x00 |
| `12_bootstrap_ack_rebootstrap.{json,bin}`   | BOOTSTRAP_ACK status=0x01 |

All keys and randomness in `.in.json` are FIXED so the `.out.bin` is
byte-reproducible across implementations.

Every conformant implementation MUST pass all vectors:
- `encode(inputs) == out.bin` byte-exactly
- `decode(out.bin) → inputs` round-trip

---

## 16. Compatibility and extension

**No protocol version field, intentionally.** The magic bytes `Echo` are
the permanent protocol identifier. Any change to the wire format that
would break existing implementations is, by definition, a different
protocol and ships on a different UDP port (and a different name, if
publicly identified).

**Forward-compatible extension points:**

- **`msg_type` (primary).** 256 values, 7 used. New `msg_type` values can
  be added at any time. Old implementations silently drop unknown types
  (per §12).
- **Reserved bits in status bytes (secondary).** STATUS_DETAIL's
  `status_and_blocks` byte and BOOTSTRAP_ACK's `status` byte have
  explicitly-reserved bits (v1 senders MUST zero, v1 receivers MUST
  ignore). Future versions can use these bits for informational signals
  that v1 receivers safely ignore.

Reserved msg_type ranges:

- `0x05–0x0f`: future authenticated node-query types.
- `0x11–0x1f`: future unauthenticated witness-reply types.
- `0x22–0x2f`: future bootstrap-related types.
- `0x30+`: cluster-management or other extensions.

No specific extension is committed to in v1.

---

## 17. Security notes (v1)

**In scope:**
- Forgery prevention: AEAD on all authenticated traffic.
- Confidentiality + integrity of cluster_key delivery: ChaCha20-Poly1305
  over X25519 ECDH ephemeral-static.
- Confidentiality of authenticated payloads: ChaCha20 stream cipher per
  cluster.
- Replay rejection: strict-monotonic timestamp_ms per sender; receiver-
  side `last_rx_timestamp` tracking.
- Anti-DDoS: per-source-IP token bucket; UNKNOWN_SOURCE rate limit.

**Out of scope / known limitations:**
- **No forward secrecy** for cluster_key against compromise of
  `witness_secret`. A future leak of witness_secret allows decryption of
  captured BOOTSTRAPs. Mitigation: operational rotation of the witness
  X25519 keypair.
- **Cluster_key is one shared secret per cluster.** Compromise of any
  cluster member or the witness leaks cluster_key, allowing forgery
  and decryption of cluster traffic. Acceptable for LAN; for higher-
  sensitivity deployments, the application encrypts payloads at its
  own layer before placing them in `own_payload`.
- **No post-quantum primitives.**
- **No third-party-verifiable witness statements.** If a future use case
  needs externally-verifiable witness output (audit logs, cross-org
  attestations), a v2 message type with Ed25519 (or PQ-sig) signature
  trailer can be added.
- **DISCOVER and UNKNOWN_SOURCE are unauthenticated by necessity.**
  Trust in the witness's pubkey comes from out-of-band channels (DNSSEC
  TXT, operator config, TOFU + human verification).

---

## Appendix A — Recovery-after-total-outage using the 128-byte payload

**Non-normative.** This appendix describes a design pattern applications
may build on top of Echo. It is not part of the wire format.

### A.1 Problem

A two-node cluster experiences a total power outage. One node dies
permanently; the other comes back hours later. The survivor must decide
whether it is safe to resume serving data unilaterally. Without external
evidence, it cannot distinguish "peer died while we were synchronised"
(safe) from "peer had newer data I never saw" (unsafe).

### A.2 Ingredients

- A battery-backed witness that retains its RAM state across the outage
  (a few-hour UPS-grade battery, matching the witness's age-out window).
- Nodes that include their current application state (e.g., DRBD UUIDs,
  Raft log tip hashes) in each HEARTBEAT's `own_payload` field.
- **The invariant: a node MUST advertise its new intended state via
  heartbeat, and verify that the witness recorded it (via STATUS_DETAIL
  self-query), BEFORE taking any action that would persist the state
  change.**

### A.3 The advertise-verify-act pattern

```
Node about to take a persistent action (promote, write, elect self):

  1. Prepare the new state locally (compute new UUID, log entry, …).
  2. HEARTBEAT the witness with the new state as own_payload:
        intent: "I'm about to become Primary of resource R, new uuid X"
  3. STATUS_DETAIL self-query:
        query_target_id = my_sender_id
  4. If witness's stored payload == what I sent in step 2:
        → the intent is externally recorded
        → proceed with step 5
     Else (packet loss, witness offline, rate-limited, …):
        → abort or retry from step 2
  5. Perform the actual action locally.
  6. HEARTBEAT again with the completed state:
        committed: "I am Primary of R, uuid=X"
```

### A.4 Why this is safe

The invariant combined with witness durability guarantees: if a state
change reached completion, its intent was recorded by the witness first.
Therefore, for any node that has silently gone away, the witness's
last-recorded payload reflects either:

- The state at which that node last successfully advertised intent
  (which, if never followed by a completion, means it never actually
  took the action), or
- The state after a completed action.

Either way, a surviving node can read its peer's last-known state via
STATUS_DETAIL, compare to its own local state, and know whether the two
sides diverged.

### A.5 Recovery decision rule (DRBD example)

```
Survivor S boots after outage. Queries STATUS_DETAIL for peer P:

  S_state = local DRBD uuid
  P_state = witness's recorded P payload
  P_age   = peer_seen_ms_ago in witness's reply

  If P_age < network_blip_threshold (e.g., 30 seconds):
      → peer is alive and booting too. Hold; converge via peer-to-peer.
  Else if P_state.uuid == S_state.uuid:
      → we were synchronised at peer's last-known checkpoint.
      → no writes happened since.
      → SAFE to promote (following advertise-verify-act for the promotion).
  Else if P_state.uuid newer than S_state.uuid:
      → peer had data we don't.
      → UNSAFE; refuse; alert operator.
  Else if P_state.uuid older than S_state.uuid:
      → we are ahead. Proceed.

  If witness has no record of P (age-out or witness reboot):
      → no external evidence. UNSAFE; operator intervention required.
```

### A.6 Failure mode coverage

| Failure | Behaviour |
|---|---|
| Witness also lost power (battery dead) | No peer record → refuse auto-promote → alert operator |
| Peer partially returned and wrote during outage | Peer's last_seen is recent, newer uuid → mismatch detected, survivor refuses |
| Two nodes boot simultaneously | Both see peer's last_seen is tiny (< threshold) → both hold → peer-to-peer sync wins |
| Survivor crashes between step 4 (verified) and step 5 (action) | Intent recorded but action not executed → on reboot, recovery logic can safely re-drive (idempotent actions only) or flag for operator |
| Survivor crashes between step 5 (action) and step 6 (announce completion) | Local state advanced but witness doesn't know → next boot, local-state > witness-view-of-self triggers "advance witness first, then continue" |

### A.7 Payload schema is application-defined

Each application defines its own opaque payload schema. DRBD would put
per-resource UUIDs and roles. A Raft implementation would put term and
last-applied-index. Bedrock specifically uses a cluster-log tip hash
(see `docs/bedrock-cluster-log.md`). The Echo witness treats all of
these identically — N × 32 bytes of opaque per-node application state.
