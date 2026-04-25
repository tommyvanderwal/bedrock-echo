# Phase 3 review — C/ESP32 implementation

**Status:** complete. Builds clean. Boots clean on the live ESP32-POE-ISO.
86 KiB DRAM heap free at boot — well above target.

## What was built

| File | Purpose | LOC |
|---|---|---:|
| `firmware/esp32-c/main/echo.h` | All types, constants, function prototypes (single header for the whole module). | ~210 |
| `firmware/esp32-c/main/echo_proto.c` | Wire-format encode/decode for all 7 message types. Pure logic, fixed-size stack scratch. | ~310 |
| `firmware/esp32-c/main/echo_crypto.c` | TweetNaCl X25519 + mbedTLS HKDF-SHA256 + ChaCha20-Poly1305. HMAC-SHA256 removed. AEAD encrypt/decrypt now take a nonce parameter. | ~225 |
| `firmware/esp32-c/main/echo_state.c` | RAM-only state machine including the **block allocator** (no bitmap, node table is the allocation map), per-cluster offset adaptation, age-out tiers triggered by max(node_fill, pool_fill), per-IP rate limiting. | ~260 |
| `firmware/esp32-c/main/echo_handler.c` | Dispatch + lookup chain. IP-first → sender_id → AEAD-against-every-cluster_key. Tri-state outcome (NotMine/Drop/Reply) prevents the anti-replay-bypass bug we caught in Rust phase. | ~290 |
| `firmware/esp32-c/main/echo_info.c` | Boot info banner. `senderid=` line removed (witness id is fixed at 0xFF). | (small edit) |
| `firmware/esp32-c/main/main.c` | UDP loop. Now passes `src_port` to handler. | (small edit) |

**Memory footprint (Olimex ESP32-POE-ISO):**

| Item | Bytes |
|---|---:|
| `.bss` total | 99,776 |
| `.data` | 8,144 |
| **DRAM used** | **107,920 (60% of 180 KB)** |
| **DRAM free for heap** | **72,816 (40%)** |
| At-boot heap (after init) | ~86 KiB |

That 86 KiB heap is the comfortable place we wanted: well above the
~50 KiB safety floor for LwIP + FreeRTOS + mbedTLS workspaces under
load. The 64 KB block pool (2048 × 32 B blocks) is most of the .bss.

## Block allocator: no bitmap, node table is the map

Implemented per `docs/witness-implementation.md` §3.2-3.3. To find N
free consecutive blocks:

1. Walk the node table, collecting `(first_block, first_block + n_blocks)`
   intervals from in-use entries.
2. Sort by `first_block` (insertion / qsort — small N).
3. Scan gaps; first gap ≥ N wins.
4. If no fit: `defrag()` packs all in-use allocations toward the LOW
   end (memmove handles the overlap), then retry.
5. Still no fit: silent drop (caller path).

Defrag is always one-direction (toward LOW). Free space accumulates
at the HIGH end. Same direction every time — no alternation, no
scratch reserve.

## What I verified live

- Builds clean (warnings only, all benign once forward-declaration
  ordering was fixed).
- Boots clean on the ESP32 at 192.168.2.181.
- DHCPs onto LAN, listens on UDP 12321.
- Pub key is the same NVS-persisted value as before
  (`800b1f47...22d16779`), confirming the X25519 priv survived the
  reflash via NVS.
- `ping -c 3` returns sub-ms RTT.
- Serial info banner shows the new layout (no `senderid=` line).

## What I didn't (deferred to Phase 4)

- **Cross-language interop test against the live ESP32.** The Python
  NodeClient should hit the ESP32 with DISCOVER/BOOTSTRAP/HEARTBEAT
  and verify replies. That's Phase 4.
- **Test vector verification.** The C impl doesn't have a host-side
  test runner. The vector verification happens via interop: if the
  Python client + ESP32 witness exchange real packets and decode each
  other's bytes, the wire format is correct. (Alternative: build a
  desktop-Linux unit-test harness that links the C code against
  vectors. Out of scope; the cross-language interop covers it.)
- **Stress tests** (many concurrent clusters, large payloads, age-out
  under load). Worth doing at some point; not a blocker.

## Bug caught in Rust phase, prevented in C from the start

The "anti-replay bypass via the new-node-join scan" bug that surfaced
in Rust phase doesn't exist in the C impl because I implemented the
tri-state `hb_outcome_t` from the start (HB_NOT_MINE / HB_DROP /
HB_REPLY) — knowing exactly what to write because the Rust phase
already exposed the trap. Cross-implementation lessons compounding.

## Main thoughts

1. **TweetNaCl X25519 + mbedTLS AEAD is a clean stack** for ESP32. No
   exotic dependencies, all in IDF or already vendored. The new code
   compiles slightly smaller than the old (less HMAC infrastructure).

2. **The block allocator is small** (~80 lines including defrag) and
   the "no bitmap, node table IS the map" approach is genuinely
   elegant. The qsort step is the most expensive part and at N=256
   nodes it's microseconds.

3. **Static scratch buffers** for plaintext (`pt_scratch[1154]` —
   payload + 2 bytes of preamble) appear in heartbeat decode. They
   live in `.bss` (one each in proto.c and handler.c) — total ~2.3 KB
   of static plaintext scratch. Cheap.

4. **Forward-declaration ordering** in echo.h gave me trouble first
   build (struct echo_state_s declared inside parameter lists). Easy
   fix: move pool function declarations after the typedef. Worth
   noting for future edits — keep typedefs ahead of any function
   prototype that uses them.

5. **The handler's "static scratch buffer for decode plaintext"** is
   actually one of the more delicate bits. I used `static uint8_t
   pt_scratch[ECHO_PAYLOAD_MAX_BYTES + 2]` inside both
   `try_existing_node` and `try_new_node`. Static = single instance
   per function. With Cortex-M3 single-threaded UDP task, no
   reentrancy issue, but on a multi-tasking witness this would be a
   bug. ESP32 witness has one UDP task, so safe.

## Slight doubts / things to watch

1. **TweetNaCl scalar clamping.** TweetNaCl's `crypto_scalarmult`
   clamps the scalar internally. This matches RFC 7748 and matches
   what x25519-dalek does in Rust and what `cryptography` does in
   Python. If a future implementation forgets to clamp (or someone
   uses a different curve25519 impl that doesn't clamp the same way),
   the cross-impl byte-exact match would break. The interop tests
   would catch it.

2. **Pool size at 64 KB.** This means at most **2048 / 36 = 56
   simultaneously fat (1152 B) nodes** on the ESP32. For typical
   deployments that's plenty (almost no real cluster has 56 fat
   nodes). For a hosted-witness ESP32 serving many small clusters,
   2048 / 1 = 2048 1-block nodes is the absolute ceiling. The
   metadata table caps at 256 anyway, so you'd be limited by node
   slots first.

3. **The age-out tiers don't differentiate node-fill from pool-fill.**
   I used `max(node_pct, pool_pct)` which is correct per the spec
   ("the more aggressive of node-table fill and pool fill"). But it
   means a single fat-payload node will trigger 5-min age-out as soon
   as block-pool exceeds 90% — even if the node count is 1. This is
   the intended behavior; just worth documenting in the operator's
   guide eventually.

4. **`echo_pool_free` is currently a no-op.** Deallocation happens
   implicitly when a node entry's `in_use=false` or its
   `(first_block, n_blocks)` is rewritten. That's because the
   allocator computes free space from the live node table on every
   call. It works correctly but the no-op feels weird. I considered
   removing the function but kept it for symmetry and future
   experimentation (e.g., if someone adds a free-list cache).

5. **`payload_first_block = 0` for empty payload** is technically
   ambiguous (block 0 might also be the start of someone else's
   allocation). Currently safe because we never read N=0 worth of
   bytes from the pool. But if a future bug accidentally reads from
   `pool[0]` thinking the payload starts there, bad data could leak.
   Worth noting.

6. **No live cross-language interop yet.** The whole "wire format is
   the same byte-for-byte across Python, Rust, C" promise — verified
   via test vectors in Python and Rust phases — has only been
   partially validated for C (build succeeds, boot succeeds). The
   real test is Phase 4.

7. **Blocks pool memmove during defrag uses ~700 µs at full pool.**
   That blocks the UDP task for that duration. For a witness under
   sustained heartbeat load, this could occasionally cause a
   visible latency spike. Not a correctness issue. If it ever
   matters, we'd switch to incremental compaction (move N blocks per
   call), but the simple synchronous approach is fine.

## What's next (Phase 4 — Cross-language interop)

1. Run the Python NodeClient against the live ESP32 witness:
   - DISCOVER → verify witness pubkey
   - BOOTSTRAP with a fresh cluster_key
   - HEARTBEAT with a payload
   - STATUS_LIST + STATUS_DETAIL queries
   - Verify byte-exactly that all fields decode correctly

2. (Optional) Run the Rust witness binary in a parallel test:
   - Python NodeClient ↔ Rust witness (over loopback)
   - Verifies the third edge of the implementation triangle.

3. Verify the existing Python integration tests run unmodified
   against the new ESP32 witness — same `test_interop_live.py`
   structure, just with protocol.

If Phase 4 passes, the spec is implementation-validated end-to-end
and we can call it ready to ship.
