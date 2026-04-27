"""Generate Bedrock Echo test vectors.

Run from the repo root:
    PYTHONPATH=python python3 testvectors/generate.py

Each vector is a pair: NN_name.in.json (inputs) + NN_name.out.bin
(the exact bytes that should appear on the UDP wire).

All inputs are FIXED so the .out.bin is byte-reproducible across
implementations. Conformant implementations encode the inputs of
each .in.json and compare byte-for-byte against the corresponding
.out.bin; they also decode .out.bin and compare back to inputs.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "python"))

from echo import proto  # noqa: E402

OUT_DIR = Path(__file__).resolve().parent

# Fixed across all vectors for reproducibility
CLUSTER_KEY = bytes(range(0x10, 0x30))                   # 32 B, 0x10..0x2F
WITNESS_PRIV = bytes([0xAA] * 32)                        # 32 B
WITNESS_PUB = None  # filled in below from priv via X25519
WITNESS_COOKIE_SECRET = bytes([0xCC] * 32)               # 32 B (fixed for cookie repro)
EPH_PRIV = bytes([0xBB] * 32)                            # 32 B (fixed for BOOTSTRAP repro)

# Fixed src_ip for vectors that require a cookie. 192.0.2.10 is in TEST-NET-1.
BOOTSTRAP_SRC_IP = bytes([192, 0, 2, 10])                # 4 B, network byte order
BOOTSTRAP_COOKIE = None  # filled in below from secret + src_ip

NODE_A_ID = 0x01
NODE_B_ID = 0x02
NODE_C_ID = 0x03
WITNESS_ID = proto.WITNESS_SENDER_ID  # 0xFF

TS_NODE_HB = 1_700_000_000_000           # ms since epoch (2023-11-14)
TS_WITNESS_REPLY = 1_700_000_000_050     # 50 ms later
TS_BOOTSTRAP = 1_700_000_001_000
TS_DISCOVER = 1_699_999_999_500


def hexstr(b: bytes) -> str:
    return b.hex()


def write_pair(name: str, inputs: dict, wire_bytes: bytes):
    in_path = OUT_DIR / f"{name}.in.json"
    out_path = OUT_DIR / f"{name}.out.bin"
    with in_path.open("w") as f:
        json.dump(inputs, f, indent=2, sort_keys=False)
        f.write("\n")
    with out_path.open("wb") as f:
        f.write(wire_bytes)
    print(f"  wrote {name}: {len(wire_bytes)} B")


def main():
    global WITNESS_PUB, BOOTSTRAP_COOKIE
    from echo import crypto
    WITNESS_PUB = crypto.x25519_pub_from_priv(WITNESS_PRIV)
    BOOTSTRAP_COOKIE = crypto.derive_cookie(WITNESS_COOKIE_SECRET, BOOTSTRAP_SRC_IP)

    print("Generating Bedrock Echo test vectors")
    print(f"  output dir: {OUT_DIR}")
    print()

    # 01: HEARTBEAT list query (no own_payload)
    hb = proto.Heartbeat(
        sender_id=NODE_A_ID,
        timestamp_ms=TS_NODE_HB,
        query_target_id=proto.QUERY_LIST_SENTINEL,  # 0xFF = LIST
        own_payload=b"",
    )
    inputs = {
        "description": "HEARTBEAT with query_target_id=0xFF (request LIST), empty own_payload",
        "msg_type": "0x01 HEARTBEAT",
        "cluster_key": hexstr(CLUSTER_KEY),
        "sender_id": NODE_A_ID,
        "timestamp_ms": TS_NODE_HB,
        "query_target_id": 0xFF,
        "own_payload": "",
    }
    write_pair("01_heartbeat_list_query", inputs, hb.encode(CLUSTER_KEY))

    # 02: HEARTBEAT detail query with 4-block (128 B) payload
    payload_2 = (b"role=primary,uuid=0xdeadbeef" + b"\x00" * (128 - 28))[:128]
    hb2 = proto.Heartbeat(
        sender_id=NODE_A_ID,
        timestamp_ms=TS_NODE_HB + 1,
        query_target_id=NODE_B_ID,
        own_payload=payload_2,
    )
    inputs = {
        "description": "HEARTBEAT with query_target_id=0x02 (DETAIL for peer B), 4-block payload",
        "msg_type": "0x01 HEARTBEAT",
        "cluster_key": hexstr(CLUSTER_KEY),
        "sender_id": NODE_A_ID,
        "timestamp_ms": TS_NODE_HB + 1,
        "query_target_id": NODE_B_ID,
        "own_payload": hexstr(payload_2),
    }
    write_pair("02_heartbeat_detail_query", inputs, hb2.encode(CLUSTER_KEY))

    # 03: HEARTBEAT self-query (Appendix A pattern), 1-block payload
    payload_3 = (b"intent=promote-R" + b"\x00" * (32 - 16))[:32]
    hb3 = proto.Heartbeat(
        sender_id=NODE_A_ID,
        timestamp_ms=TS_NODE_HB + 2,
        query_target_id=NODE_A_ID,  # self-query
        own_payload=payload_3,
    )
    inputs = {
        "description": "HEARTBEAT with query_target_id == own sender_id (Appendix A self-query), 1-block payload",
        "msg_type": "0x01 HEARTBEAT",
        "cluster_key": hexstr(CLUSTER_KEY),
        "sender_id": NODE_A_ID,
        "timestamp_ms": TS_NODE_HB + 2,
        "query_target_id": NODE_A_ID,
        "own_payload": hexstr(payload_3),
    }
    write_pair("03_heartbeat_self_query", inputs, hb3.encode(CLUSTER_KEY))

    # 04: STATUS_LIST with 2 entries
    sl = proto.StatusList(
        timestamp_ms=TS_WITNESS_REPLY,
        witness_uptime_seconds=3600,
        entries=(
            proto.ListEntry(peer_sender_id=NODE_A_ID, last_seen_ms=42),
            proto.ListEntry(peer_sender_id=NODE_B_ID, last_seen_ms=1503),
        ),
    )
    inputs = {
        "description": "STATUS_LIST reply with 2 entries (caller A + peer B)",
        "msg_type": "0x02 STATUS_LIST",
        "cluster_key": hexstr(CLUSTER_KEY),
        "timestamp_ms": TS_WITNESS_REPLY,
        "witness_uptime_seconds": 3600,
        "entries": [
            {"peer_sender_id": NODE_A_ID, "last_seen_ms": 42},
            {"peer_sender_id": NODE_B_ID, "last_seen_ms": 1503},
        ],
    }
    write_pair("04_status_list_two_nodes", inputs, sl.encode(CLUSTER_KEY))

    # 05: STATUS_LIST empty
    sl_empty = proto.StatusList(
        timestamp_ms=TS_WITNESS_REPLY + 1,
        witness_uptime_seconds=10,
        entries=(),
    )
    inputs = {
        "description": "STATUS_LIST reply with 0 entries (newly bootstrapped witness)",
        "msg_type": "0x02 STATUS_LIST",
        "cluster_key": hexstr(CLUSTER_KEY),
        "timestamp_ms": TS_WITNESS_REPLY + 1,
        "witness_uptime_seconds": 10,
        "entries": [],
    }
    write_pair("05_status_list_empty", inputs, sl_empty.encode(CLUSTER_KEY))

    # 06: STATUS_DETAIL found, 4-block peer_payload
    peer_payload_6 = (b"primary, drbd-uuid=B-deadbeef" + b"\x00" * (128 - 29))[:128]
    sd = proto.StatusDetail(
        timestamp_ms=TS_WITNESS_REPLY + 2,
        witness_uptime_seconds=3601,
        target_sender_id=NODE_B_ID,
        found=True,
        peer_ipv4=proto.ipv4_to_bytes("192.168.2.11"),
        peer_seen_ms_ago=1500,
        peer_payload=peer_payload_6,
    )
    inputs = {
        "description": "STATUS_DETAIL reply for peer B (found), 4-block peer_payload",
        "msg_type": "0x03 STATUS_DETAIL",
        "cluster_key": hexstr(CLUSTER_KEY),
        "timestamp_ms": TS_WITNESS_REPLY + 2,
        "witness_uptime_seconds": 3601,
        "target_sender_id": NODE_B_ID,
        "found": True,
        "peer_ipv4": "192.168.2.11",
        "peer_seen_ms_ago": 1500,
        "peer_payload": hexstr(peer_payload_6),
    }
    write_pair("06_status_detail_found", inputs, sd.encode(CLUSTER_KEY))

    # 07: STATUS_DETAIL not found
    sd_nf = proto.StatusDetail(
        timestamp_ms=TS_WITNESS_REPLY + 3,
        witness_uptime_seconds=3602,
        target_sender_id=NODE_C_ID,
        found=False,
    )
    inputs = {
        "description": "STATUS_DETAIL reply for peer C (not found)",
        "msg_type": "0x03 STATUS_DETAIL",
        "cluster_key": hexstr(CLUSTER_KEY),
        "timestamp_ms": TS_WITNESS_REPLY + 3,
        "witness_uptime_seconds": 3602,
        "target_sender_id": NODE_C_ID,
        "found": False,
    }
    write_pair("07_status_detail_not_found", inputs, sd_nf.encode(CLUSTER_KEY))

    # 08: DISCOVER (64 B, zero-padded for anti-amplification, caps=0)
    disc = proto.Discover(sender_id=NODE_A_ID, timestamp_ms=TS_DISCOVER,
                          capability_flags=0)
    inputs = {
        "description": "DISCOVER probe (64 B). 14 B header + 2 B caps + 48 B zero pad. "
                       "Caps default 0 in Draft v0.x.",
        "msg_type": "0x04 DISCOVER",
        "sender_id": NODE_A_ID,
        "timestamp_ms": TS_DISCOVER,
        "capability_flags": 0,
        "padding_bytes": 48,
    }
    write_pair("08_discover", inputs, disc.encode())

    # 09: INIT with witness_pubkey + cookie + caps=0
    init = proto.Init(
        timestamp_ms=TS_WITNESS_REPLY + 4,
        witness_pubkey=WITNESS_PUB,
        cookie=BOOTSTRAP_COOKIE,
        capability_flags=0,
    )
    inputs = {
        "description": "INIT reply (64 B): pubkey + cookie + 16-bit witness capability_flags",
        "msg_type": "0x10 INIT",
        "timestamp_ms": TS_WITNESS_REPLY + 4,
        "witness_pubkey": hexstr(WITNESS_PUB),
        "witness_cookie_secret": hexstr(WITNESS_COOKIE_SECRET),
        "src_ip": ".".join(str(b) for b in BOOTSTRAP_SRC_IP),
        "cookie": hexstr(BOOTSTRAP_COOKIE),
        "capability_flags": 0,
    }
    write_pair("09_init", inputs, init.encode())

    # 10: BOOTSTRAP (fixed eph_priv + cookie for reproducibility)
    bs = proto.Bootstrap(
        sender_id=NODE_A_ID,
        timestamp_ms=TS_BOOTSTRAP,
        cluster_key=CLUSTER_KEY,
        cookie=BOOTSTRAP_COOKIE,
    )
    bs_wire = bs.encode(WITNESS_PUB, EPH_PRIV)
    inputs = {
        "description": "BOOTSTRAP delivering cluster_key with cookie in AAD (fixed eph_priv)",
        "msg_type": "0x20 BOOTSTRAP",
        "sender_id": NODE_A_ID,
        "timestamp_ms": TS_BOOTSTRAP,
        "cluster_key": hexstr(CLUSTER_KEY),
        "witness_pubkey": hexstr(WITNESS_PUB),
        "witness_cookie_secret": hexstr(WITNESS_COOKIE_SECRET),
        "src_ip": ".".join(str(b) for b in BOOTSTRAP_SRC_IP),
        "cookie": hexstr(BOOTSTRAP_COOKIE),
        "eph_priv": hexstr(EPH_PRIV),
    }
    write_pair("10_bootstrap", inputs, bs_wire)

    # 11: BOOTSTRAP_ACK new (status=0x00)
    ack_new = proto.BootstrapAck(
        timestamp_ms=TS_BOOTSTRAP + 50,
        status=0x00,
        witness_uptime_seconds=3600,
    )
    inputs = {
        "description": "BOOTSTRAP_ACK status=0x00 (new entry created)",
        "msg_type": "0x21 BOOTSTRAP_ACK",
        "cluster_key": hexstr(CLUSTER_KEY),
        "timestamp_ms": TS_BOOTSTRAP + 50,
        "status": 0x00,
        "witness_uptime_seconds": 3600,
    }
    write_pair("11_bootstrap_ack_new", inputs, ack_new.encode(CLUSTER_KEY))

    # 12: BOOTSTRAP_ACK idempotent (status=0x01)
    ack_re = proto.BootstrapAck(
        timestamp_ms=TS_BOOTSTRAP + 51,
        status=0x01,
        witness_uptime_seconds=3601,
    )
    inputs = {
        "description": "BOOTSTRAP_ACK status=0x01 (idempotent re-bootstrap)",
        "msg_type": "0x21 BOOTSTRAP_ACK",
        "cluster_key": hexstr(CLUSTER_KEY),
        "timestamp_ms": TS_BOOTSTRAP + 51,
        "status": 0x01,
        "witness_uptime_seconds": 3601,
    }
    write_pair("12_bootstrap_ack_rebootstrap", inputs, ack_re.encode(CLUSTER_KEY))

    # MANIFEST file
    manifest = """\
Bedrock Echo test vectors
============================

These vectors are the canonical cross-language contract for the protocol.
Every conformant implementation MUST:
  1. Encode the inputs in each .in.json byte-exactly to the corresponding .out.bin
  2. Decode each .out.bin and round-trip back to inputs

Vectors:
  01  HEARTBEAT list-query, empty payload                        (cluster_key)
  02  HEARTBEAT detail-query for peer B, 4-block payload          (cluster_key)
  03  HEARTBEAT self-query (Appendix A), 1-block payload          (cluster_key)
  04  STATUS_LIST with 2 entries                                  (cluster_key)
  05  STATUS_LIST empty                                           (cluster_key)
  06  STATUS_DETAIL found, 4-block peer_payload                   (cluster_key)
  07  STATUS_DETAIL not found                                     (cluster_key)
  08  DISCOVER (62 B, zero-padded)                                (no auth)
  09  INIT with witness_pubkey + cookie                           (no auth)
  10  BOOTSTRAP (fixed eph_priv, fixed cookie)                    (X25519 + AEAD)
  11  BOOTSTRAP_ACK status=0x00 (new)                             (cluster_key)
  12  BOOTSTRAP_ACK status=0x01 (idempotent)                      (cluster_key)

Reproducibility constants (in .in.json files):
  cluster_key            = 0x10..0x2F (32 bytes)
  witness_priv           = 0xAA × 32  (used to derive witness_pubkey)
  witness_cookie_secret  = 0xCC × 32  (used to derive cookies in 09/10)
  eph_priv               = 0xBB × 32  (used in BOOTSTRAP)
  node A id              = 0x01
  node B id              = 0x02
  node C id              = 0x03
  witness id             = 0xFF
  bootstrap src_ip       = 192.0.2.10  (for cookie derivation in 09/10)
"""
    (OUT_DIR / "MANIFEST").write_text(manifest)
    print()
    print("Done. Vectors written to:", OUT_DIR)


if __name__ == "__main__":
    main()
