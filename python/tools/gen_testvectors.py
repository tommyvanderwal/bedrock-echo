"""Generate the canonical test-vector files under testvectors/.

Each vector is a pair:
  NN_name.in.json   — inputs (keys, payload, sequence, timestamp, randomness)
  NN_name.out.bin   — exact bytes on the wire

Both Python and Rust test suites read the .in.json, encode, and assert the
result equals .out.bin byte-for-byte. Then decode .out.bin and check against
.in.json.

Everything in .in.json is hex-encoded bytes or plain integers. Keep it
implementation-agnostic.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from echo import proto, crypto  # noqa: E402

OUT_DIR = Path(__file__).resolve().parents[2] / "testvectors"
OUT_DIR.mkdir(exist_ok=True)


# Fixed inputs used across vectors — deliberately NOT random.

CLUSTER_KEY = bytes.fromhex(
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
)
SID_A = bytes.fromhex("aa11aa22aa33aa44")
SID_B = bytes.fromhex("bb11bb22bb33bb44")
SID_W = bytes.fromhex("ee11ee22ee33ee44")   # witness's own sender_id

WITNESS_PRIV = bytes(range(0x20, 0x40))      # 32 bytes
WITNESS_PUB = crypto.x25519_pub_from_priv(WITNESS_PRIV)

EPH_PRIV = bytes(range(0x40, 0x60))          # 32 bytes
EPH_PUB = crypto.x25519_pub_from_priv(EPH_PRIV)

# Clock: deliberately fixed, no `time.time()` anywhere.
TS = 1_700_000_000_000


def hx(b: bytes) -> str:
    return b.hex()


def write_vector(name: str, inputs: dict, wire: bytes) -> None:
    json_path = OUT_DIR / f"{name}.in.json"
    bin_path = OUT_DIR / f"{name}.out.bin"
    json_path.write_text(json.dumps(inputs, indent=2) + "\n")
    bin_path.write_bytes(wire)
    print(f"  wrote {name}: {len(wire)} bytes ({bin_path.name}, {json_path.name})")


def v01_heartbeat_list_query() -> None:
    hb = proto.Heartbeat(
        sender_id=SID_A, sequence=1, timestamp_ms=TS,
        query_target_id=b"\x00" * 8,
        own_payload=b"role=primary,disk=UpToDate",
    )
    wire = hb.encode(CLUSTER_KEY)
    write_vector("01_heartbeat_list_query", {
        "description": "HEARTBEAT with query_target_id=0 (request topology list)",
        "msg_type": "0x01 HEARTBEAT",
        "cluster_key": hx(CLUSTER_KEY),
        "sender_id": hx(SID_A),
        "sequence": 1,
        "timestamp_ms": TS,
        "query_target_id": hx(b"\x00" * 8),
        "own_payload": hx(hb.own_payload),
    }, wire)


def v02_heartbeat_detail_query() -> None:
    hb = proto.Heartbeat(
        sender_id=SID_A, sequence=2, timestamp_ms=TS,
        query_target_id=SID_B,
        own_payload=b"role=primary,conn=Connected,disk=UpToDate,uuid=0xfeed",
    )
    wire = hb.encode(CLUSTER_KEY)
    write_vector("02_heartbeat_detail_query", {
        "description": "HEARTBEAT asking for detail on peer B",
        "msg_type": "0x01 HEARTBEAT",
        "cluster_key": hx(CLUSTER_KEY),
        "sender_id": hx(SID_A),
        "sequence": 2,
        "timestamp_ms": TS,
        "query_target_id": hx(SID_B),
        "own_payload": hx(hb.own_payload),
    }, wire)


def v03_status_list_two_nodes() -> None:
    entries = (
        proto.ListEntry(peer_sender_id=SID_A,
                        peer_ipv4=proto.ipv4_to_bytes("192.168.2.10"),
                        last_seen_seconds=1),
        proto.ListEntry(peer_sender_id=SID_B,
                        peer_ipv4=proto.ipv4_to_bytes("192.168.2.11"),
                        last_seen_seconds=3),
    )
    sl = proto.StatusList(
        sender_id=SID_W, sequence=1, timestamp_ms=TS,
        witness_uptime_ms=60_000, entries=entries,
    )
    wire = sl.encode(CLUSTER_KEY)
    write_vector("03_status_list_two_nodes", {
        "description": "STATUS_LIST reply with two node entries",
        "msg_type": "0x02 STATUS_LIST",
        "cluster_key": hx(CLUSTER_KEY),
        "witness_sender_id": hx(SID_W),
        "sequence": 1,
        "timestamp_ms": TS,
        "witness_uptime_ms": 60_000,
        "entries": [
            {"peer_sender_id": hx(SID_A),
             "peer_ipv4": "192.168.2.10",
             "last_seen_seconds": 1},
            {"peer_sender_id": hx(SID_B),
             "peer_ipv4": "192.168.2.11",
             "last_seen_seconds": 3},
        ],
    }, wire)


def v04_status_detail_found() -> None:
    sd = proto.StatusDetail(
        sender_id=SID_W, sequence=2, timestamp_ms=TS,
        witness_uptime_ms=60_000,
        target_sender_id=SID_B, status=0x00,
        peer_ipv4=proto.ipv4_to_bytes("192.168.2.11"),
        last_seen_seconds=3,
        peer_payload=b"role=secondary,conn=Connected,disk=UpToDate,uuid=0xfeed",
    )
    wire = sd.encode(CLUSTER_KEY)
    write_vector("04_status_detail_found", {
        "description": "STATUS_DETAIL for peer B, found",
        "msg_type": "0x03 STATUS_DETAIL",
        "cluster_key": hx(CLUSTER_KEY),
        "witness_sender_id": hx(SID_W),
        "sequence": 2,
        "timestamp_ms": TS,
        "witness_uptime_ms": 60_000,
        "target_sender_id": hx(SID_B),
        "status": 0,
        "peer_ipv4": "192.168.2.11",
        "last_seen_seconds": 3,
        "peer_payload": hx(sd.peer_payload),
    }, wire)


def v05_status_detail_not_found() -> None:
    sd = proto.StatusDetail(
        sender_id=SID_W, sequence=3, timestamp_ms=TS,
        witness_uptime_ms=60_000,
        target_sender_id=bytes.fromhex("1234567890abcdef"),
        status=0x01,
    )
    wire = sd.encode(CLUSTER_KEY)
    write_vector("05_status_detail_not_found", {
        "description": "STATUS_DETAIL for unknown target, not-found",
        "msg_type": "0x03 STATUS_DETAIL",
        "cluster_key": hx(CLUSTER_KEY),
        "witness_sender_id": hx(SID_W),
        "sequence": 3,
        "timestamp_ms": TS,
        "witness_uptime_ms": 60_000,
        "target_sender_id": "1234567890abcdef",
        "status": 1,
    }, wire)


def v06_unknown_source() -> None:
    us = proto.UnknownSource(sender_id=SID_W, sequence=1, timestamp_ms=TS)
    wire = us.encode()
    write_vector("06_unknown_source", {
        "description": "UNKNOWN_SOURCE reply (unauthenticated, no payload, no trailer)",
        "msg_type": "0x10 UNKNOWN_SOURCE",
        "witness_sender_id": hx(SID_W),
        "sequence": 1,
        "timestamp_ms": TS,
    }, wire)


def v07_bootstrap() -> None:
    bs = proto.Bootstrap(
        sender_id=SID_A, sequence=100, timestamp_ms=TS,
        cluster_key=CLUSTER_KEY,
        init_payload=b"role=primary",
    )
    wire = bs.encode(WITNESS_PUB, EPH_PRIV)
    write_vector("07_bootstrap", {
        "description": ("BOOTSTRAP packet. Deterministic: fixed witness keypair, "
                        "fixed ephemeral priv, fixed cluster_key, fixed init_payload."),
        "msg_type": "0x20 BOOTSTRAP",
        "witness_x25519_priv": hx(WITNESS_PRIV),
        "witness_x25519_pub": hx(WITNESS_PUB),
        "eph_priv": hx(EPH_PRIV),
        "eph_pub": hx(EPH_PUB),
        "sender_id": hx(SID_A),
        "sequence": 100,
        "timestamp_ms": TS,
        "cluster_key": hx(CLUSTER_KEY),
        "init_payload": hx(bs.init_payload),
    }, wire)


def v08_bootstrap_ack_new() -> None:
    ack = proto.BootstrapAck(
        sender_id=SID_W, sequence=1, timestamp_ms=TS,
        status=0x00, witness_uptime_ms=1_500,
    )
    wire = ack.encode(CLUSTER_KEY)
    write_vector("08_bootstrap_ack_new", {
        "description": "BOOTSTRAP_ACK with status=0x00 (new cluster installed)",
        "msg_type": "0x21 BOOTSTRAP_ACK",
        "cluster_key": hx(CLUSTER_KEY),
        "witness_sender_id": hx(SID_W),
        "sequence": 1,
        "timestamp_ms": TS,
        "status": 0,
        "witness_uptime_ms": 1_500,
    }, wire)


def v09_bootstrap_ack_rebootstrap() -> None:
    ack = proto.BootstrapAck(
        sender_id=SID_W, sequence=2, timestamp_ms=TS,
        status=0x01, witness_uptime_ms=123_000,
    )
    wire = ack.encode(CLUSTER_KEY)
    write_vector("09_bootstrap_ack_rebootstrap", {
        "description": "BOOTSTRAP_ACK with status=0x01 (idempotent re-bootstrap)",
        "msg_type": "0x21 BOOTSTRAP_ACK",
        "cluster_key": hx(CLUSTER_KEY),
        "witness_sender_id": hx(SID_W),
        "sequence": 2,
        "timestamp_ms": TS,
        "status": 1,
        "witness_uptime_ms": 123_000,
    }, wire)


VECTORS = [
    v01_heartbeat_list_query,
    v02_heartbeat_detail_query,
    v03_status_list_two_nodes,
    v04_status_detail_found,
    v05_status_detail_not_found,
    v06_unknown_source,
    v07_bootstrap,
    v08_bootstrap_ack_new,
    v09_bootstrap_ack_rebootstrap,
]


if __name__ == "__main__":
    print(f"Generating vectors in {OUT_DIR}")
    for fn in VECTORS:
        fn()
    # Also emit a MANIFEST for discoverability
    (OUT_DIR / "MANIFEST").write_text(
        "# Bedrock Echo v0.001 canonical test vectors\n"
        "# Each pair of files below must be parsed identically by every impl.\n"
        + "\n".join(sorted(p.name for p in OUT_DIR.iterdir()
                           if p.name.endswith((".bin", ".json"))))
        + "\n"
    )
    print("done.")
