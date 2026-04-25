# Phase 4 review — Cross-language interop

**Status:** complete. **8/8 interop tests pass live against the ESP32
witness.** Wire format byte-exact across Python, Rust, and C.

## What was tested

Python NodeClient ↔ ESP32 witness firmware over real LAN UDP.
Every message type exercised end-to-end:

| Test | Message types | Result |
|---|---|---|
| `test_discover_returns_witness_pubkey` | DISCOVER → UNKNOWN_SOURCE | ✓ |
| `test_heartbeat_first_with_auto_bootstrap` | HEARTBEAT → UNKNOWN_SOURCE → BOOTSTRAP → ACK → HEARTBEAT → STATUS_LIST | ✓ |
| `test_explicit_bootstrap` | BOOTSTRAP → ACK | ✓ |
| `test_two_nodes_join_same_cluster` | First node BOOTSTRAPs, second node HEARTBEATs into existing cluster (new-node-join scan) | ✓ |
| `test_status_detail_for_peer` | HEARTBEAT(query=peer) → STATUS_DETAIL with peer's payload | ✓ |
| `test_self_query_appendix_a` | HEARTBEAT(query=self) → STATUS_DETAIL — Appendix A advertise-verify-act pattern | ✓ |
| `test_status_detail_for_unknown_peer` | HEARTBEAT(query=nonexistent) → STATUS_DETAIL not_found | ✓ |
| `test_max_payload` | 36-block (1152 B) payload round-trip | ✓ |

```
$ pytest python/tests/test_interop_live.py -v
============================ 8 passed in 13.70s ==============================
```

## Combined test counts

| Implementation | Tests passing |
|---|---:|
| Python: protocol unit tests | 47 |
| Python: test vectors (12 vectors round-trip byte-exact) | 13 |
| Python: witness state machine | 19 |
| Python: end-to-end via UDP loopback | 7 |
| Python: cross-language interop vs. ESP32 | 8 |
| **Python total** | **94** |
| Rust: test vectors (12 + nonce derivation) | 15 |
| Rust: witness state machine | 8 |
| **Rust total** | **23** |
| **Grand total** | **117 tests across all 3 implementations** |

## Bug caught and fixed in Phase 4

**Heartbeat-first flow couldn't recover from rate-limited
UNKNOWN_SOURCE.** The original NodeClient retried bootstrap only on
explicit UNKNOWN_SOURCE replies. If the witness silent-dropped the
UNKNOWN_SOURCE due to rate limit, the heartbeat just timed out and
the client gave up.

Fix: NodeClient now treats heartbeat timeout as "probable rate-limited
UNKNOWN_SOURCE — bootstrap unconditionally and retry." The bootstrap
itself is cryptographically authenticated (ECDH to the configured
witness pubkey), so this isn't a security risk.

## Operational note: rate limit + tight test loops

The full Python suite when run repeatedly against the same witness
(without resetting) can fail interop tests due to interaction between:

1. Per-IP rate limit (10 pps + 20 burst) at the witness.
2. Per-IP UNKNOWN_SOURCE limit (1/s) at the witness.
3. Stale node entries from previous test runs persisting across runs
   (until age-out in 72 h).
4. Random per-test-run cluster_keys (so previous entries can't be
   AEAD-verified against the new key, but they're still in the table).

When running the full suite against a fresh witness, all 8 interop
tests pass. When running it back-to-back without reset, the rate-limit
budget can starve.

**This is correct witness behavior.** The rate limit is doing its
job. The "fix" is operational: either reset the witness between
test runs, or set a longer `recv_timeout_s` on the NodeClient and
let the witness's budget refresh.

For production deployments, this is a non-issue: real heartbeat
cadence is one packet every 2 seconds, well under the 10 pps cap.

## What this proves

The cross-language byte-exact contract via test vectors gave us
high-confidence wire-format compatibility on day one. Phase 4 turned
that into mechanical-end-to-end verification:

- Python Heartbeat encoded under cluster_key → ESP32 mbedTLS
  AEAD-decrypts byte-exact.
- ESP32 STATUS_DETAIL encoded under cluster_key → Python AEAD-decrypts
  byte-exact.
- BOOTSTRAP X25519 ECDH path matches exactly across the languages
  (Python's `cryptography` and ESP32's TweetNaCl produce identical
  shared secrets, identical HKDF outputs, identical aead_keys).
- Every byte position, every field encoding, every nonce derivation
  matches.

The Bedrock Echo protocol is now implementation-validated
end-to-end across three reference implementations on three different
crypto stacks (Python `cryptography`, Rust `RustCrypto`, ESP32
TweetNaCl + mbedTLS).

## What's next (post-polish)

Now that the implementation is complete:

1. **Reference implementations in 2 more languages** (per the
   user's vision of 5+ implementations). Probably Go and JavaScript,
   or Go and Java. Each new impl validates the spec further.

2. **Hosted-witness service** on AWS t4g.nano-class instances.
   Per design-notes, one nano can serve ~10 K clusters. Three
   geographically-distributed witnesses + DNSSEC TXT distribution =
   "default witness set for any 2-node Bedrock cluster" as a free
   service.

3. **Bedrock node daemon** integration: replace the existing daemon's
   witness client with the new NodeClient.

4. **DRBD pilot**: re-run the existing DRBD scenario harness against
   the witness (the harness is at `harness/scenarios.py` per the
   project's earlier session notes). All 11 scenarios should pass.

5. **NanoKVM Lite**: cross-compile the Rust witness binary for the
   SG2002 platform once that hardware is set up (per the user's
   earlier interest).

The protocol is shippable. The implementations work. The contract
holds.
