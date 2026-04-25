# Phase 2 review — Rust implementation

**Status:** complete. 23 tests passing (15 vectors byte-exact + 8 witness
state-machine).

## What was built

| Crate / module | Purpose | LOC |
|---|---|---:|
| `crates/bedrock-echo-proto/src/constants.rs` | All wire-format constants. | ~50 |
| `crates/bedrock-echo-proto/src/lib.rs` | Top-level error enum, public re-exports. | ~40 |
| `crates/bedrock-echo-proto/src/header.rs` | 14-byte header + nonce derivation. | ~70 |
| `crates/bedrock-echo-proto/src/crypto.rs` | X25519, HKDF-SHA256, ChaCha20-Poly1305 wrappers (no_std). | ~85 |
| `crates/bedrock-echo-proto/src/msg.rs` | All 7 message types: encoders write into caller buffers; decoders verify in-place AEAD. | ~430 |
| `crates/bedrock-echo-witness/src/state.rs` | RAM-only state with per-cluster offset, monotonic timestamps, age-out, rate limit. | ~225 |
| `crates/bedrock-echo-witness/src/handler.rs` | Dispatch + lookup chain. IP-first, sender_id fallback, new-node-join scan, anti-replay. | ~310 |
| `crates/bedrock-echo-witness/src/lib.rs` | Library re-exports so tests can drive the state machine. | 8 |
| `crates/bedrock-echo-witness/src/main.rs` | Linux UDP loop. | ~100 |
| `crates/bedrock-echo-proto/tests/test_vectors.rs` | 12 vector tests + 3 nonce-derivation tests. | 15 tests |
| `crates/bedrock-echo-witness/tests/test_state_machine.rs` | State machine tests covering bootstrap, idempotent re-bootstrap, collision-resolution, new-node-join, anti-replay, DISCOVER. | 8 tests |

**Cross-language byte-for-byte match:** all 12 test vectors produce
identical output between Python and Rust. The contract is real.

## Bug caught during impl

**Anti-replay bypass via the new-node-join scan.** When a HEARTBEAT
arrived with a timestamp ≤ `last_rx_timestamp` (a replay), the
candidate-AEAD-trial path correctly returned `None`, but the dispatcher
then fell through to the new-node-join scan, which AEAD-verified the
SAME packet against the same cluster_key (because that's the cluster
the candidate already belonged to) and would have allocated a NEW
node entry for it.

Fix: candidate-trial now returns a tri-state outcome — `NotMine` (try
next candidate), `Drop` (silent drop, do not fall through), or
`Reply`. AEAD-success-but-rejected is `Drop`. Belt-and-suspenders: the
new-node-join path also checks "is there already an entry for this
sender_id in this cluster" and returns `Drop` if so.

Test that caught it: `anti_replay_blocks_duplicate_timestamp` — same
test the Python impl has but with the timing slightly different (the
Python state model can't fall into this trap because it uses HashMaps
keyed by sender_id; Rust's array-based state allowed multiple entries
to silently coexist).

This is exactly the kind of bug that having parallel implementations
catches: the test vectors caught nothing wrong here (they don't
exercise multi-packet flows), but having two parallel state machines
with different storage layouts surfaced the difference.

## Crypto crate notes

- HMAC dependency dropped. `Cargo.toml` is now: `sha2 + hkdf +
  x25519-dalek + chacha20poly1305`. Minimum useful set.
- HKDF info string updated to `b"bedrock-echo bootstrap"` (was
  `b"bedrock-echo bootstrap"`).
- AEAD nonce is now derived per-packet from the header (was hardcoded
  zero in the old design — only correct for BOOTSTRAP, which is the
  one place we keep zero-nonce because the aead_key is fresh per
  packet).
- AEAD encrypt/decrypt take a `nonce: &[u8; 12]` parameter; the
  `BOOTSTRAP_NONCE` constant is the all-zero nonce kept as a named
  constant for clarity.

## Witness state model notes

- `NodeEntry.sender_id` is now `u8` (was `[u8; 8]`).
- `NodeEntry.payload` is `[u8; PAYLOAD_MAX_BYTES]` (1152). Wastes RAM
  vs the block-allocator design that ESP32 will use, but it's the
  simplest correct thing in a Rust/std environment.
- `ClusterEntry.cluster_offset` is `i64` (can be negative early on).
- `ClusterEntry.last_tx_timestamp` enforces strict-monotonic outgoing
  timestamps for AEAD nonce uniqueness.
- `find_nodes_by_sender` returns an iterator over multiple matches
  (collision-resolution requires this).
- The `handle()` entry point now takes `src_port: u16` for future
  caching of `(src_ip, src_port) → cluster_key` matches; it's stored
  but not yet used to optimize lookups.

## Main thoughts

1. **The vector tests are the strong contract.** Once the Rust impl
   passes them byte-exact, all the wire-level mechanics are validated.
   Even a small bug in nonce derivation or HKDF info would have shown
   up there.

2. **The state-machine tests are the weak contract.** They probe the
   witness's behavior at a much higher level than vectors. They caught
   the new-node-join replay bug, which is exactly what they're for.

3. **Rust's borrow checker fights with the dispatch logic.** The
   "decrypt in place, then mutate state" pattern wants to borrow
   `state` mutably for the AEAD region while still keeping access to
   the cluster table. I worked around this with stack-local copy
   buffers (`let mut buf = [0u8; MTU_CAP]; buf[..data.len()].copy_from_slice(data)`)
   which is what one wants on no_std anyway. Slight overhead per call
   that didn't exist in Python (where slicing is cheap).

4. **`heapless::Vec`** ended up useful in the dispatch logic for
   building the `candidates` list and for the `payload_owned` copy
   of the decrypted plaintext. Avoids allocation; bounds-checked.

5. **The Rust witness binary builds clean** but I haven't actually
   spun it up against a Python NodeClient yet. That's deliberately
   Phase 4 (cross-language interop) — getting the impls right
   first, then verifying they really talk to each other over UDP.

## Slight doubts / things to watch

1. **`StaticSecret::from(bytes)` in x25519-dalek 2.x** automatically
   clamps the scalar before any operation. Good — means we don't need
   to manually clamp the eph_priv bytes. But if some other language
   (looking at you, ESP32 with TweetNaCl) doesn't auto-clamp, we
   could have a subtle interop bug. The test vectors should catch
   this; if vector_10_bootstrap matches byte-for-byte across
   languages, both clamp the same way.

2. **`heapless` 0.8 vs 0.9.** I used 0.8 because cargo found a
   compatible version pre-resolved. The 0.9 version has minor API
   differences (`from_slice` returns slightly different types).
   Worth migrating later, but not urgent.

3. **Array-based state vs HashMap.** Python uses `dict` and `list`;
   Rust uses fixed-size arrays. The fixed-size design is correct for
   ESP32 portability but makes Linux-side iteration more verbose.
   The reference impl is fine; an "optimized hosted-witness" Rust
   crate later might want a separate non-no_std build that uses
   `HashMap<sender_id, Vec<NodeEntry>>` for fast lookups at scale.

4. **Defensive bounds in `try_handle_existing_node`.** I `return
   HbOutcome::Drop` on `payload_owned` allocation failure — but the
   payload is at most 1152 B and `heapless::Vec<u8, 1152>` can hold
   it. The path is unreachable in practice but the defensive code is
   there as a safety net.

5. **The `Reply` type is a 1400-byte buffer + length.** Stack-allocated
   per call. Each `handle()` invocation builds one of these. On
   embedded that's fine; on Linux it's also fine but a bit wasteful.
   Could return a borrowed slice instead, but lifetime gymnastics
   aren't worth the optimization.

6. **No test for the rate limiter on the Rust side.** The Python tests
   cover the per-IP-rate-limited UNKNOWN_SOURCE behavior; I didn't
   re-port that to Rust. The state machine code is straight-line
   identical, but it'd be nice to have explicit verification.
   Adding to phase-3 todos for the C/ESP32 phase if I find time.

7. **`witness_priv` vs `witness_secret` naming.** The Rust code calls
   it `witness_priv` (matching the pre-existing code); the Python
   code uses both `priv` and `witness_secret` interchangeably; the
   spec uses `witness_secret`. Inconsistency is cosmetic but worth a
   future cleanup.

## Test counts

- Python total: 86 tests passing (Phase 1)
- Rust total: 23 tests passing (this phase)
- Combined: **109 tests across two implementations, with 12 vectors
  byte-exact in both**.

## What's next (Phase 3 — C/ESP32)

The biggest, most novel phase:

1. **Block allocator** for payload storage (no bitmap; node table is
   the allocation map; same-direction defrag).
2. **AEAD-everywhere via mbedTLS** ChaCha20-Poly1305.
3. **Wire format** matching the new spec.
4. **Collision-resolution lookup** with IP-first filter and new-node-join scan.
5. **Per-cluster offset** machinery (no NTP path).
6. **DISCOVER** handler.

Build, flash to the live ESP32 at 192.168.2.181 (per the project
notes), verify it boots, and run a Python interop test against it.

Confidence going in: high. The Python and Rust impls agree byte-for-byte
on all 12 vectors; if the C impl agrees on those, the wire-level
semantics are tested 3-way.
