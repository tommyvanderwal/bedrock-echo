# Phase 1 review — Python reference implementation

**Status:** complete. 86 tests passing. Test vectors generated.

## What was built

| Module | Purpose | LOC |
|---|---|---:|
| `python/echo/crypto.py` | Three primitives only (X25519, HKDF-SHA256, ChaCha20-Poly1305). HMAC dropped. | ~75 |
| `python/echo/proto.py` | Full new wire format. 7 message types, AEAD nonce derivation, block-granular payloads, status-byte forward-compat patterns. | ~395 |
| `python/echo/witness.py` | RAM-only witness state machine. IP-first lookup, sender_id fallback, new-node-join scan, per-cluster offset, anti-replay, age-out tiers. | ~330 |
| `python/echo/node.py` | NodeClient. HEARTBEAT-first with auto-BOOTSTRAP on UNKNOWN_SOURCE. DISCOVER. Strict-monotonic timestamps. | ~115 |
| `testvectors/generate.py` | Generator for 12 canonical vectors using fixed inputs. | ~190 |
| `python/tests/test_protocol.py` | Encode/decode round-trips, error paths, AEAD nonce semantics, forward-compat (bit-6 / upper-bits) tolerance. | 47 tests |
| `python/tests/test_vectors.py` | Loads each `.in.json`, verifies encode == `.out.bin` byte-exact, decode round-trips. | 13 tests |
| `python/tests/test_witness.py` | State machine tests: BOOTSTRAP path, HEARTBEAT path, new-node-join, anti-replay, rate limiting, cluster offset, cross-cluster isolation. | 19 tests |
| `python/tests/test_end_to_end.py` | NodeClient ↔ Witness over real UDP loopback. Threaded witness, full DISCOVER/BOOTSTRAP/HEARTBEAT flows. | 7 tests |

**Total: 86 tests, all passing in ~0.8 s.**

## Test vectors

12 canonical vectors covering all 7 message types and key edge cases:

```
01  HEARTBEAT list-query, empty payload                  32 B
02  HEARTBEAT detail-query for peer B, 4-block payload  160 B
03  HEARTBEAT self-query, 1-block payload                64 B
04  STATUS_LIST with 2 entries                           45 B
05  STATUS_LIST empty                                    35 B
06  STATUS_DETAIL found, 4-block peer_payload           172 B
07  STATUS_DETAIL not found                              36 B
08  DISCOVER                                             14 B
09  UNKNOWN_SOURCE with witness_pubkey                   46 B
10  BOOTSTRAP (fixed eph_priv)                           94 B
11  BOOTSTRAP_ACK status=0x00                            35 B
12  BOOTSTRAP_ACK status=0x01                            35 B
```

All `.in.json` fixtures use deterministic keys (`cluster_key = 0x10..0x2F`,
`witness_priv = 0xAA × 32`, `eph_priv = 0xBB × 32`) so any conformant
implementation can reproduce the `.out.bin` byte-exactly.

## Bug caught during impl

**Spec arithmetic error in PROTOCOL.md.** I had written
`STATUS_DETAIL found = 60 + 32N B` and `not found = 52 B`, but the actual
math is `44 + 32N` and `36`. I had double-counted the AEAD tag. Caught it
when the generator output sizes didn't match the spec's stated values;
fixed PROTOCOL.md to match the implementation's correct arithmetic.

## Main thoughts

1. **The new wire format is genuinely cleaner than v0.** ~12% smaller for
   typical small messages, encrypted payload, fewer crypto primitives,
   simpler header. The AEAD-everywhere decision in particular pays off:
   one primitive consistently used means one consistent error path for
   "wrong key / tampered packet".

2. **Forward-compat patterns work as intended.** The status_and_blocks
   byte in STATUS_DETAIL has explicit tests for "v2 sender sets bit 6,
   receiver ignores it" — passes. Same for BOOTSTRAP_ACK's upper bits.
   This gives us a documented, tested extension mechanism that isn't the
   "MUST be zero" trap.

3. **Per-cluster offset is unsurprising in the reference impl.** Wrote it
   straight from the spec; no edge cases bit me. Will be more interesting
   on ESP32 where the implementation is C and there's no spare RAM to be
   sloppy.

4. **The new-node-join scan path was the most subtle piece.** Took some
   thought to wire correctly: try IP+sender_id, fall back to sender_id,
   fall back to AEAD-vs-every-cluster-key. The test (Node B joins A's
   cluster via plain HEARTBEAT, no BOOTSTRAP needed) exercises it cleanly.

5. **Anti-replay across the protocol uses one primitive (`timestamp_ms`)
   for two distinct purposes** (replay rejection AND AEAD nonce
   uniqueness). The MUST-strict monotonic-per-sender rule on senders is
   load-bearing for both. Tests cover replay-with-same-timestamp,
   replay-with-older-timestamp, and the burst case (10 packets at the
   same wall-clock ms produce 10 distinct timestamps).

## Slight doubts / things to watch

1. **The AEAD nonce derivation** `sender_id || 0x000000 || timestamp_ms`
   is correct for our threat model but worth re-verifying when implementing
   in Rust and C. Specifically the "0x000000" padding bytes: I implemented
   them as `b"\x00\x00\x00"` literal — that's fine in Python where struct
   strings handle this, but Rust/C will need to be explicit about
   little-endian-vs-big-endian byte order in the rest of the nonce.
   The spec says timestamp_ms is BE, sender_id is one byte (no endianness
   needed). Should be unambiguous but worth a re-check.

2. **Witness sender_src_port tracking.** The witness stores `sender_src_port`
   for the cache optimization mentioned in `witness-implementation.md` §1.3,
   but the Python reference doesn't actually USE it for caching — it just
   stores it. Linear scan over candidates is fine for the reference's
   small N. Real implementations should add the cache; flagged for Rust/C.

3. **STATUS_LIST in a cluster with N=128 entries** is at the MTU edge —
   1191 B with 209 B slack. Not exercised in the reference implementation
   tests because N=128 is a rare scenario. The unit test
   `test_status_list_max_entries_fits_mtu` does exercise this path with
   the LARGER 128-entry list and confirms it fits, but we don't have an
   end-to-end test that triggers it under load. Worth a stress test in
   later phases if hosted-witness scale becomes a real deployment.

4. **The "same nonce visible in keystream" test** is mostly defensive —
   it verifies that two different plaintexts at the same nonce produce
   different ciphertexts, but not that we'd actually generate them in
   practice (we wouldn't, because of the strict-monotonic rule). It's
   a safety-net: if a future bug breaks the nonce derivation, this test
   would fail noisily. Renaming to be clearer about what it tests would
   be nice.

5. **Rate-limiter test only checks the per-IP UNKNOWN_SOURCE 1/sec rule**,
   not the general 10 pps token bucket. The general rate limit is
   straightforward but un-exercised. Add a stress test in Rust phase if
   we want confidence in the witness's anti-flood behavior.

6. **No test for the witness running out of node slots / cluster slots /
   block-pool space.** The reference impl handles these (returns silent
   drop), but no test asserts the silent-drop. Easy to add, marginal
   value at this size — but if the C/ESP32 impl has a bug in its block
   allocator that returns uninitialised memory or crashes, those tests
   would catch it. Adding for Phase 3.

7. **The `payload_len` field in the witness state was removed** (per the
   spec's block-granular wire format). I matched this in the Python impl —
   the witness stores exactly `n_blocks × 32` bytes, no separate length.
   But interactions with the block allocator in C might want `payload_len`
   back. Will see in Phase 3.

8. **`Witness.handle_packet` returns a list of (bytes, dst) tuples** —
   currently always 0 or 1 items, but the API allows more. No multi-reply
   case yet. Future use case might be: witness re-broadcasts a state to
   multiple peers. Speculative; current design doesn't need it.

9. **The unauthenticated DISCOVER flow** doesn't validate the source IP
   or rate-limit aggressively beyond the standard 1/sec/IP. A scanner
   probing many witnesses across the internet would get an UNKNOWN_SOURCE
   reply from each, which costs witness bandwidth. Acceptable per spec,
   but worth a per-implementation deployment guidance note.

## What's next (Phase 2 — Rust)

The Rust implementation should be a mechanical translation of the Python
reference plus the test vectors. Specifically:

1. `crates/bedrock-echo-proto`: encode/decode with same wire format.
   Pass all 12 test vectors byte-exact.
2. `crates/bedrock-echo-witness`: same state machine. Re-port the
   tests (or call Python tests against a Rust binary?).
3. Drop the `hmac` dependency from `Cargo.toml` — only `chacha20poly1305`,
   `x25519-dalek`, `hkdf`, `sha2` needed.
4. Same nonce derivation. Same forward-compat tolerances. Same
   collision-resolution semantics.

Cross-language verification:
- Each Rust unit test runs against vectors → byte-exact.
- A Rust↔Python interop test (Rust witness binary, Python NodeClient)
  exercises the protocol over real UDP localhost.

I expect Rust to be the most straightforward port. The `cryptography`
crate ecosystem in Rust is mature; everything we need is in
`x25519-dalek + hkdf + sha2 + chacha20poly1305`, all well-maintained.
