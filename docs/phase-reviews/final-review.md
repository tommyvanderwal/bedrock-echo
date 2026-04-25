# Bedrock Echo — final review

**Status: shippable.** Spec frozen, three reference implementations
agree byte-for-byte, 117 tests passing across all of them, live
cross-language interop validated end-to-end.

## What was delivered

| Phase | Deliverable | Tests | Commit |
|---|---|---|---|
| 0 | PROTOCOL.md frozen spec + design-notes + witness-implementation guide | — | `13f3264` |
| 1 | Python reference impl + test vector generator + 86 tests | 86 | `6748ff5` |
| 2 | Rust impl (proto + witness crates), drops HMAC dependency | 23 | `a467eb4` |
| 3 | C/ESP32 firmware with block allocator, AEAD-everywhere | (live boot) | `d8740c7` |
| 4 | Cross-language interop validated against live ESP32 | 8 | (this commit) |

Total: **117 unit/integration tests** plus **live interop verification**
that Python NodeClient ↔ ESP32 firmware exchange real packets
correctly over real LAN UDP.

## What changed from where we started this session

Wire format (header alone went from 32 B → 14 B):

| | pre-Echo | Echo |
|---|---|---|
| Header | 32 B (magic + msg_type + reserved + 8B sender_id + 8B sequence + 8B timestamp + 2B payload_len) | **14 B** (magic + msg_type + 1B sender_id + 8B timestamp) |
| Sender_id | 8 B | **1 B** (collision-resolved via AEAD trial) |
| Auth on steady-state messages | HMAC-SHA256 (32 B trailer) | **AEAD ChaCha20-Poly1305** (16 B tag) |
| Payload encryption | None | **All authenticated payloads encrypted** |
| Payload size cap | 128 B | **1152 B** (36 × 32 B blocks, mandatory variable) |
| Message types | 6 | **7** (added DISCOVER) |
| Bootstrap carries init_payload | Yes | **No** (single-purpose: just delivers cluster_key) |
| State delivery on first-time node | Always BOOTSTRAP | **HEARTBEAT-first**; BOOTSTRAP only when needed |
| Cluster_key rotation | Hard | **Coexisting clusters via collision-resolution** |
| Forward-compat extension points | reserved-byte trap | **flag bits in status bytes (defined-as-ignored)** + msg_type |
| Crypto primitives needed | X25519, HMAC-SHA256, HKDF-SHA256, ChaCha20-Poly1305 | **X25519, HKDF-SHA256, ChaCha20-Poly1305** (one fewer) |

## Bytes-on-the-wire savings

Typical small-cluster heartbeat exchange (HEARTBEAT 64 B + 16 B
own_payload, then STATUS_DETAIL reply 96 B + 32 B peer_payload):

| | pre-Echo | Echo | Savings |
|---|---:|---:|---:|
| HEARTBEAT (with 16 B own_payload) | 88 B | 64 B | 27% |
| STATUS_DETAIL reply (with 32 B peer_payload) | 123 B | 76 B | 38% |
| Combined per round-trip | 211 B | 140 B | **34%** |

At hosted-witness scale (10 K clusters × ~0.5 round-trips/sec) that's
**~6 GB/day saved per 10 K-cluster cohort**, ~$0.50/day at AWS egress
rates.

## Bugs caught during the implementation pass

1. **Spec arithmetic error**: STATUS_DETAIL totals were stated as
   "60 + 32N B / 52 B" — I had double-counted the AEAD tag. Actual
   sizes: 44 + 32N / 36 B. Caught when generator output didn't match
   spec; fixed in Phase 1.

2. **Anti-replay bypass via new-node-join scan** (Rust phase): a
   replayed HEARTBEAT was being accepted as "new node" because the
   candidate-trial path returned None (drop), then the dispatcher
   fell through to the new-node-join scan, which AEAD-verified the
   same packet under the same cluster_key. Fixed via tri-state
   outcome (NotMine / Drop / Reply) and belt-and-suspenders existence
   check. Rust caught it; C avoided it from the start.

3. **Heartbeat-first couldn't recover from rate-limited
   UNKNOWN_SOURCE** (Phase 4): NodeClient only re-bootstrapped on
   explicit UNKNOWN_SOURCE reply. If silent-dropped due to rate
   limit, the client gave up. Fixed by treating timeout as
   "probable rate-limited UNKNOWN_SOURCE → bootstrap and retry."

## Memory profile (ESP32-POE-ISO big build)

| Item | Bytes |
|---|---:|
| `.bss` total (state structures) | 99,776 |
| `.data` | 8,144 |
| **DRAM used** | **107,920 (60% of 180 KB)** |
| Heap remaining at boot | **~86 KiB** |
| Block pool | 64 KB (2048 × 32 B blocks) |
| Node table | 256 entries |
| Cluster table | 128 entries |
| Rate-limit table | 192 entries |
| Max simultaneously fat-payload nodes | 56 (1152 B each) |

Heap headroom of 86 KiB is comfortably above the ~50 KiB safety
floor for LwIP + FreeRTOS + mbedTLS workspaces under load.

## Lessons learned (for the next protocol I help design)

1. **Test vectors are the strongest cross-language contract.** Once
   they pass byte-exact in all three impls, the wire format is
   validated. Everything else is implementation correctness.

2. **Parallel implementations catch real bugs.** The anti-replay bug
   wasn't visible in the Python state model because Python uses
   HashMaps keyed by sender_id (and naturally couldn't fall into
   the trap). It surfaced in Rust because of fixed-size arrays. In
   C I avoided it because Rust had taught me the lesson.

3. **Forward-compat patterns require two distinct mechanisms** that
   look superficially similar but are very different in practice:
   - "MUST be zero" reserved bytes are a TRAP — they prevent any
     future use because old parsers reject non-zero.
   - "Defined as ignored, senders MUST zero" reserved bits are a
     real extension point — old parsers ignore them, new versions
     can use them.

4. **The AEAD nonce derivation tied to the strict-monotonic
   timestamp_ms** rule is doubly load-bearing (anti-replay AND
   nonce-uniqueness). Both rely on the same MUST-strict rule on
   senders. Belt-and-suspenders against the same root cause.

5. **Block-granular payloads with no bitmap** are surprisingly
   elegant. Node table IS the allocation map. ~80 lines of C
   including same-direction defrag.

6. **Rate limits in tests are operationally annoying.** A per-IP
   rate limit at the witness combined with a tight test loop
   creates failures that look like protocol bugs but are actually
   test-infrastructure issues. Worth documenting clearly so future
   developers don't chase phantoms.

## Items deferred / not yet supported

These were explicitly noted for later review and not blocking ship:

1. **Forward secrecy** for cluster_key delivery: not achievable in
   single-message protocol against a static recipient. Operational
   compensation: rotate the witness's X25519 keypair periodically.

2. **Cluster-key rotation** as a first-class protocol feature:
   resolved by collision-resolution semantics — operators bootstrap
   nodes into a new cluster (parallel cluster on same witness) and
   let old age out. No protocol-level rotation needed.

3. **IPv6**: deferred. Add via new msg_types (e.g., STATUS_LIST_V6,
   STATUS_DETAIL_V6) when a real deployment needs it.

4. **More than 3 reference implementations**: Go and JavaScript
   (or Go and Java) would validate the spec further. Not blocking.

5. **DNSSEC pubkey distribution rollout**: spec describes the format
   (`v=Echo; k=x25519; p=BASE64`) but no zone is published yet.

## What's ready to ship

- `PROTOCOL.md` — frozen wire spec.
- `docs/witness-implementation.md` — normative implementation guide.
- `docs/design-notes.md` — design rationale (non-normative).
- `docs/adoption/README.md` — per-system integration notes.
- `docs/bedrock-cluster-log.md` — Bedrock-specific cluster log design.
- `docs/phase-reviews/` — this rollout's progression.
- `python/echo/` — reference implementation, 94 tests passing.
- `crates/bedrock-echo-{proto,witness}/` — Rust impl, 23 tests passing.
- `firmware/esp32-c/` — ESP32 firmware, builds clean, boots clean,
  passes live interop.
- `testvectors/` — 12 canonical vectors. Generator script. MANIFEST.

## Sign-off

The Bedrock Echo protocol is shippable. The implementation pass
is complete. The cross-language interop is verified live. Time to
build things on top of it.
