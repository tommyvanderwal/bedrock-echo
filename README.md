# Echo

A small UDP **witness protocol** for split-brain prevention in cluster software.

Two-node clusters can't safely vote among themselves — they need an external
tiebreaker. Echo is the smallest correct thing for that job: a stateless,
reactive witness that nodes can ask "did you hear from my peer recently, and
what did it last tell you?" The witness never decides, never votes, never
initiates — it just remembers a tiny opaque payload per cluster member and
serves it back on request.

```
   node A ──┐                          ┌── node B
            │   HEARTBEAT  (32 B + N)  │
            ├──────────────────────────┤
            │   STATUS_DETAIL          │
            └──────► witness ◄─────────┘
```

The witness can be an ESP32 on a desk, a 700 KB static binary in an AWS
region, a container on a MikroTik router, or anything in between.

**Protocol status: Draft v0.x.**

The current wire format is stable enough for interoperability testing,
but not frozen. Breaking changes may still happen before v1.0 based on
implementation feedback, security review, and BedRock integration
testing. Three reference implementations agree byte-for-byte via 12
canonical test vectors, and live cross-language interop is verified —
but until BedRock has run on top of Echo in production for a while,
the wire is open to change.

If you're considering a fourth implementation: now is the moment to
review and push back. Once v1.0 ships into hardware that's never going
to be touched again, the wire is immutable forever (different
protocols thereafter use different UDP ports, not new Echo versions).


## What's in the repo

| Path                                  | What                                                              |
|---|---|
| [`PROTOCOL.md`](PROTOCOL.md)          | Authoritative wire-format spec                                    |
| [`docs/witness-implementation.md`](docs/witness-implementation.md) | Normative implementation guide for witness authors |
| [`docs/design-notes.md`](docs/design-notes.md) | Design rationale, rejected alternatives, the why behind every choice |
| [`docs/adoption/`](docs/adoption/)    | How to integrate Echo into specific cluster systems (DRBD, Raft, …) |
| [`docs/phase-reviews/`](docs/phase-reviews/) | The implementation journey, with thoughts and doubts |
| `python/echo/`                        | Python reference implementation (proto + node + witness)          |
| `python/tests/`                       | 101 unit/integration/end-to-end tests                             |
| `crates/bedrock-echo-proto/`          | Rust `no_std` protocol library                                    |
| `crates/bedrock-echo-witness/`        | Rust witness binary (Linux / container) — 791 KB static-musl      |
| `firmware/esp32-c/`                   | ESP32-IDF C firmware (Olimex ESP32-POE-ISO)                       |
| `testvectors/`                        | 12 canonical `.in.json` + `.out.bin` cross-language vectors       |


## Reference implementations

| Implementation | Language | Target | Tests | LOC |
|---|---|---|---:|---:|
| Reference   | Python (`cryptography`) | any | 101 | ~1.5 K |
| Witness     | Rust (`x25519-dalek`, `chacha20poly1305`) | Linux x86_64 / aarch64, container, embeddable as `no_std` | 30 | ~1.8 K |
| Firmware    | C (TweetNaCl + mbedTLS, ESP-IDF) | ESP32-POE-ISO and similar | live boot | ~2.2 K |

All three pass the same 12 test vectors byte-exactly. Python ↔ ESP32 and
Python ↔ Rust interop is exercised over real LAN UDP in
[`python/tests/test_interop_live.py`](python/tests/test_interop_live.py).


## Highlights

- **14-byte fixed header.** No optional fields. No TLV. Every offset is known
  from `msg_type` alone.
- **Modern, common-denominator crypto.** X25519 + HKDF-SHA256 +
  ChaCha20-Poly1305. Available in every major language's stdlib and on
  ESP32 mbedTLS. No HMAC, no Ed25519, no exotic curves.
- **Strict-monotonic timestamps** double as anti-replay AND AEAD nonce
  uniqueness — one mechanism, two jobs.
- **Anti-spoofing via DNS-style cookies.** Stateless 16-byte cookies bind
  BOOTSTRAP to the requester's source IP — round-trip proof of address
  ownership, no per-flow witness state ([RFC 7873](https://www.rfc-editor.org/rfc/rfc7873.html)
  pattern). Strict `(src_ip, sender_id)` match on heartbeats blocks
  off-path injection.
- **Anti-amplification.** DISCOVER pads to match the INIT reply size
  (64 B → 64 B); the witness can never be used as a UDP reflector.
- **No protocol version field — and none needed.** The magic is `Echo`,
  forever. Forward-compat lives in two extension points that grow
  gracefully:
  - **`capability_flags`** — a 16-bit field in DISCOVER and INIT.
    Current senders zero it; future senders set bits to advertise new
    features (post-quantum bootstrap, IPv6 status types, …). Receivers
    MUST ignore bits they don't recognise.
  - **Unallocated `msg_type` values** — entirely new flows can be added
    later. Receivers silent-drop unknown types.

  **All extensions are backwards compatible with original clients.**
  Old firmware in the wild keeps working when the protocol grows; no
  version negotiation, no breaking upgrades, no firmware-in-the-wild
  failure mode. (Genuinely incompatible *different* protocols ship on
  a different UDP port with a different name — never as a "version 2"
  of Echo.)
- **RAM-only state at the witness.** Reboot loses cluster state by design;
  nodes re-bootstrap as part of normal recovery.
- **Block-granular payloads** (32 B blocks, 0..1152 B per node) align with
  the embedded witness's block allocator. No bitmap — the node table itself
  is the allocation map.
- **mDNS / DNS-SD auto-discovery on LAN.** Witnesses advertise
  `_echo._udp.local.` with the same TXT format used in the
  hosted-DNSSEC-witness scheme. One parser handles both.
- **Sized for both ends.** A Linux witness handles ~10 000 clusters on a
  t4g.nano-class instance at design-target (~40 MB RSS). ESP32 holds 256
  nodes / 128 clusters / 64 KB block pool comfortably within its 180 KB
  DRAM budget.


## Quick look — running the Rust witness

```sh
cargo build --release
./target/release/bedrock-echo-witness
# bind:           0.0.0.0:12321
# witness pub:    <hex of X25519 pubkey>
# mdns:           advertising _echo._udp as bedrock-echo-witness.local
```

Bound to UDP/12321, advertising on the LAN. Operators on the same broadcast
domain can find it without configuration:

```sh
ping bedrock-echo-witness.local            # casual
avahi-browse -tr _echo._udp                # Linux
dns-sd -B _echo._udp                       # macOS
```

Toggle the announce off with `BEDROCK_ECHO_MDNS=0`.


## Quick look — Python NodeClient

```python
from echo.node import NodeClient

n = NodeClient(
    sender_id     = 0x01,                            # 0x00..0xFE
    cluster_key   = bytes.fromhex("…"),              # 32 B, distributed by your cluster operator
    witness_addr  = ("192.168.2.181", 12321),
    witness_pubkey= bytes.fromhex("800b1f47…"),      # the trust anchor
)

# All-in-one heartbeat — auto-bootstraps via DISCOVER → INIT → BOOTSTRAP
# the first time, transparently caches the cookie afterwards.
status = n.heartbeat_list(own_payload=b"role=primary")
print(status.entries)
```

Or auto-discover via mDNS (set `WITNESS_ADDR=auto` in the daemon's env
config and supply the trust-anchor pubkey).


## Spec at a glance

| msg_type | Name           | Direction       | Auth     | Size        |
|---------:|----------------|-----------------|----------|-------------|
| `0x01`   | HEARTBEAT      | node → witness  | AEAD     | 32 + 32N B  |
| `0x02`   | STATUS_LIST    | witness → node  | AEAD     | 35 + 5N B   |
| `0x03`   | STATUS_DETAIL  | witness → node  | AEAD     | 36 / 44+32N B |
| `0x04`   | DISCOVER       | node → witness  | none     | 64 B        |
| `0x10`   | INIT           | witness → node  | none     | 64 B        |
| `0x20`   | BOOTSTRAP      | node → witness  | AEAD-DH  | 110 B       |
| `0x21`   | BOOTSTRAP_ACK  | witness → node  | AEAD     | 35 B        |

Every authenticated message uses the same 12-byte AEAD nonce derivation
(`sender_id || 0x000000 || timestamp_ms`). Replays are rejected by
strict-monotonic `timestamp_ms` per sender. See
[`PROTOCOL.md`](PROTOCOL.md) for the full byte-level layouts.


## Tests

```sh
# Python reference impl + vectors + state machine + e2e UDP-loopback
PYTHONPATH=python python3 -m pytest python/tests/ \
    --ignore=python/tests/test_interop_live.py
# 101 passed

# Rust impl + 12 cross-language vectors + state machine
cargo test
# 30 passed

# Cross-language live interop against a running witness
BEDROCK_ECHO_WITNESS_ADDR=<host:port> \
BEDROCK_ECHO_WITNESS_PUB=<hex> \
PYTHONPATH=python python3 -m pytest python/tests/test_interop_live.py
# 8 passed
```

The 12 canonical test vectors in `testvectors/` are the cross-language
contract: every conformant implementation MUST encode the inputs of each
`.in.json` to the byte-exact `.out.bin`, and decode `.out.bin` back to the
inputs.


## Use cases

Echo deliberately solves one small problem and stays out of the way. It's a
useful tiebreaker for:

- **2-node DRBD / Pacemaker / Corosync clusters** — see
  [`docs/adoption/`](docs/adoption/).
- **Raft / Paxos / etcd** clusters running `2N+1` nodes that briefly become
  `2N` after a node loss — the witness gives them a fast quorum vote
  without spinning up a third real member.
- **Custom application clusters** — anything that needs a small, low-state,
  out-of-band tiebreaker.

The protocol does not replace the cluster's own consensus or replication.
It just provides the third perspective that two nodes can never have on
their own.


## Contributing / Implementer feedback

Echo is in **draft (v0.x)** specifically to invite review by external
implementers before any wire-format gets shipped into hardware that's
never touched again. If you're writing a fourth implementation (Go,
Java, Swift, Zig, …) and something in `PROTOCOL.md` is ambiguous or
implementation-hostile, please open an issue. Wire-format change
proposals are still on the table — the threshold for "we should change
this" is much lower right now than it will be after v1.0.

The 12 test vectors and 139 tests across the existing implementations
(101 Python + 30 Rust + 8 cross-language live) are the regression net.
A fresh implementation that passes all 12 vectors byte-exactly is, by
construction, on the wire-compatible path.


## License

Dual-licensed under your choice of:

- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

This is the standard dual-license used by much of the Rust ecosystem.  
You are free to use, implement, modify, and distribute Bedrock Echo in any project (open-source or closed-source, commercial or non-commercial) with no further permission required.
