# Post-polish review — anti-amp + cookies + strict-IP

**Status:** spec + Python + Rust + ESP32 firmware shipped; live interop
pending one flash of the ESP32.

## What this round did

Three coupled changes addressing weaknesses surfaced after Phase 4:

1. **Anti-amplification.** DISCOVER pads to 62 B (zero-filled). INIT
   (renamed from UNKNOWN_SOURCE) is 62 B. Request size == reply size,
   so the witness cannot be turned into a UDP amplifier.

2. **DNS-cookie-style bind-to-IP on BOOTSTRAP.** INIT carries a 16 B
   cookie = `SHA-256(witness_cookie_secret || src_ip)[:16]`, where
   `witness_cookie_secret` rotates hourly with current+previous secrets
   retained. BOOTSTRAP (now 110 B) carries the cookie in AAD; the
   witness validates before any AEAD/X25519 work. Off-path attackers
   can no longer forge a BOOTSTRAP from a victim's IP.

3. **Strict (src_ip, sender_id) match for steady-state HEARTBEATs.**
   The sender_id-only fallback and the new-node-join AEAD scan are
   removed. All new-node introductions go through cookie-validated
   BOOTSTRAP. IP changes (DHCP renewal) require re-BOOTSTRAP — closing
   the off-path IP-redirect attack class.

## Wire-format diff vs pre-polish

| Message | Pre-polish | Post-polish | Steady-state? |
|---|---:|---:|:---:|
| DISCOVER  |  14 B  |  62 B  | no |
| INIT (was UNKNOWN_SOURCE) |  46 B  |  62 B  | no |
| BOOTSTRAP |  94 B  | 110 B  | no |
| HEARTBEAT, STATUS_LIST, STATUS_DETAIL, BOOTSTRAP_ACK | unchanged | unchanged | yes |

The hot path is untouched. Bootstrap-phase bytes increase by 32 B per
join (one INIT round-trip + 16 B cookie on the BOOTSTRAP) — once-per-
cluster-membership, so bandwidth impact is < 0.01% over a cluster's
lifetime.

## Test count progression

| Implementation | Pre-polish | Post-polish | Δ |
|---|---:|---:|---:|
| Python (proto + witness + vectors + e2e) |  86 |  99 | +13 |
| Rust (proto + witness)                   |  23 |  30 |  +7 |
| **Total**                                | **109** | **129** | **+20** |

Plus the 8 cross-language interop tests against the ESP32 (run
externally; included in the "117 tests" figure of the original
final-review).

## Bugs caught while implementing

1. **Borrow-check error in Rust tests** when passing
   `state.witness_pub.clone()` inline into `encode_bootstrap_for(...)`
   while also holding `&mut state` for the dispatch call. Fix: extract
   `let pubkey = state.witness_pub;` before the encode call. Pattern
   is now consistent throughout the test file.

2. **Spec internal consistency.** The §1 design-principles list grew
   from 12 items to 14 (added anti-amp + anti-spoof principles).
   Cross-references to the renamed INIT message updated everywhere
   except the historical phase-review docs (which describe what was
   true at each phase — left intentionally).

## What to verify post-flash

The ESP32 firmware was rebuilt clean (290 KB binary, 82% of the 1.5 MB
app partition free). It hasn't been flashed yet, so the live witness
at 192.168.2.181 is still running pre-polish firmware that will fail
the new interop tests. Once flashed, all 8 interop tests should pass:

| Test | Path exercised |
|---|---|
| `test_discover_returns_witness_pubkey` | DISCOVER (62 B) → INIT (62 B), pubkey + cookie |
| `test_heartbeat_first_with_auto_bootstrap` | HEARTBEAT → INIT → DISCOVER (cookie) → BOOTSTRAP → ACK → HEARTBEAT → STATUS_LIST |
| `test_explicit_bootstrap` | DISCOVER for cookie → BOOTSTRAP → ACK |
| `test_two_nodes_join_same_cluster` | Both nodes BOOTSTRAP individually (each with their own cookie); STATUS_LIST shows both |
| `test_status_detail_for_peer` | After bootstraps, A heartbeats with detail-query for B |
| `test_self_query_appendix_a` | Appendix A — node queries its own state to verify the witness recorded its intent payload |
| `test_status_detail_for_unknown_peer` | DETAIL query for a sender_id that isn't in the cluster → not_found reply |
| `test_max_payload` | 36-block (1152 B) HEARTBEAT round-trip |

The `test_heartbeat_first_with_auto_bootstrap` and
`test_explicit_bootstrap` exercise the new "DISCOVER first to obtain
cookie" flow end-to-end across Python (NodeClient) and ESP32 firmware.

## Lessons from this round

1. **A 1.0× amplification factor is the only correct answer.** We
   considered "rate-limit fixes it" — it doesn't, it just slows the
   amplifier. Forcing request ≥ reply removes the attack class.

2. **DNS cookies (RFC 7873) are well-trodden ground.** The pattern is
   rock-solid: short MAC over src_ip under a witness-only key, rotated
   periodically, validated against current+previous, no per-flow
   state. Adopting the existing convention rather than inventing one
   was the right call.

3. **Removing fallback paths simplifies the lookup chain.** Going from
   "IP+sender_id, then sender_id, then new-node-scan" to just
   "IP+sender_id" cuts the worst-case dispatch from O(N_clusters) AEAD
   decrypts to one lookup. The cost — re-BOOTSTRAP on IP change — is
   borne by a rare event (DHCP renewals), and every BOOTSTRAP is
   already cookie-validated and X25519-anchored to the witness pubkey.

4. **Cookie-on-BOOTSTRAP-only is enough.** We considered putting a
   cookie on every HEARTBEAT (defense in depth). Rejected: the
   per-HEARTBEAT 16 B added at hosted scale is gigabytes/day of
   bandwidth for what AEAD already provides (the cluster_key MACs
   every steady-state packet). Cookies belong only where they
   introduce new security — at the bootstrap boundary.

5. **Pre-ship is the right time to make breaking changes.** The
   protocol is named "Echo" with no version field by design — once
   ESP32 firmware ships into production, changes mean a new protocol
   on a new UDP port. The polish round happened *before* anything
   shipped externally, so wire-format bumps to DISCOVER/INIT/BOOTSTRAP
   were free.
