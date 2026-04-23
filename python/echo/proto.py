"""Bedrock Echo wire-format encode/decode.

See PROTOCOL.md for the authoritative spec. Constants and layouts match
that document byte-for-byte. Every function is pure: no I/O, no time.

Sizes and structure:
  header    = 32 bytes (magic | msg_type | flags | sender_id | sequence |
                        timestamp_ms | payload_len)
  payload   = payload_len bytes
  trailer   = 32-byte HMAC (0x01/0x02/0x03/0x21) or nothing (0x10/0x20)
"""
from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field
from typing import ClassVar

from . import crypto

MAGIC = b"BEW1"
HEADER_LEN = 32
HMAC_LEN = 32
MTU_CAP = 1400

# message types
MSG_HEARTBEAT       = 0x01
MSG_STATUS_LIST     = 0x02
MSG_STATUS_DETAIL   = 0x03
MSG_UNKNOWN_SOURCE  = 0x10
MSG_BOOTSTRAP       = 0x20
MSG_BOOTSTRAP_ACK   = 0x21

ALL_MSG_TYPES = {
    MSG_HEARTBEAT, MSG_STATUS_LIST, MSG_STATUS_DETAIL,
    MSG_UNKNOWN_SOURCE, MSG_BOOTSTRAP, MSG_BOOTSTRAP_ACK,
}

HMAC_MSG_TYPES = {
    MSG_HEARTBEAT, MSG_STATUS_LIST, MSG_STATUS_DETAIL, MSG_BOOTSTRAP_ACK,
}

NODE_PAYLOAD_MAX = 128
LIST_ENTRY_LEN = 16
LIST_MAX_ENTRIES = 64
CLUSTER_KEY_LEN = 32
EPH_PUBKEY_LEN = 32
AEAD_TAG_LEN = 16
BOOTSTRAP_INIT_PAYLOAD_MAX = 96


# ── Exceptions ─────────────────────────────────────────────────────────────


class ProtocolError(Exception):
    """Any structural / length / magic / flags violation. Caller should
    silently drop the packet that caused this (see PROTOCOL.md §12)."""


class AuthError(Exception):
    """HMAC or AEAD verification failed."""


# ── Header ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Header:
    msg_type: int
    flags: int
    sender_id: bytes        # 8 bytes
    sequence: int
    timestamp_ms: int
    payload_len: int

    _STRUCT: ClassVar[struct.Struct] = struct.Struct(">4sBB8sQqH")
    # fields: magic | msg_type | flags | sender_id | sequence | timestamp_ms | payload_len

    def pack(self) -> bytes:
        return self._STRUCT.pack(
            MAGIC,
            self.msg_type & 0xFF,
            self.flags & 0xFF,
            self.sender_id,
            self.sequence & 0xFFFFFFFFFFFFFFFF,
            self.timestamp_ms,
            self.payload_len & 0xFFFF,
        )

    @classmethod
    def unpack(cls, buf: bytes) -> "Header":
        if len(buf) < HEADER_LEN:
            raise ProtocolError(f"short header: {len(buf)} < {HEADER_LEN}")
        magic, mt, flags, sid, seq, ts, pl = cls._STRUCT.unpack_from(buf, 0)
        if magic != MAGIC:
            raise ProtocolError(f"bad magic: {magic!r}")
        if flags != 0x00:
            raise ProtocolError(f"nonzero flags: {flags:#x}")
        if mt not in ALL_MSG_TYPES:
            raise ProtocolError(f"unknown msg_type: {mt:#x}")
        if len(sid) != 8:
            raise ProtocolError("sender_id not 8 bytes")
        return cls(
            msg_type=mt, flags=flags, sender_id=bytes(sid),
            sequence=seq, timestamp_ms=ts, payload_len=pl,
        )


# ── Encode / decode per message type ───────────────────────────────────────


def _validate_sender_id(sender_id: bytes, from_node: bool) -> None:
    if len(sender_id) != 8:
        raise ProtocolError("sender_id must be 8 bytes")
    if from_node and sender_id == b"\x00" * 8:
        raise ProtocolError("sender_id == 0 invalid from node")


def _pack_hmac(packet_minus_trailer: bytes, cluster_key: bytes) -> bytes:
    return packet_minus_trailer + crypto.hmac_sha256(cluster_key, packet_minus_trailer)


def _verify_and_strip_hmac(buf: bytes, cluster_key: bytes) -> bytes:
    if len(buf) < HMAC_LEN:
        raise ProtocolError("packet shorter than HMAC tag")
    data, tag = buf[:-HMAC_LEN], buf[-HMAC_LEN:]
    if not crypto.hmac_verify(cluster_key, data, tag):
        raise AuthError("HMAC mismatch")
    return data


# ---- HEARTBEAT (0x01) ----


@dataclass(frozen=True)
class Heartbeat:
    sender_id: bytes
    sequence: int
    timestamp_ms: int
    query_target_id: bytes   # 8 bytes; 0 = list mode
    own_payload: bytes       # 0..128 bytes

    def encode(self, cluster_key: bytes) -> bytes:
        _validate_sender_id(self.sender_id, from_node=True)
        if len(self.query_target_id) != 8:
            raise ProtocolError("query_target_id must be 8 bytes")
        if len(self.own_payload) > NODE_PAYLOAD_MAX:
            raise ProtocolError(f"own_payload > {NODE_PAYLOAD_MAX}")
        payload = self.query_target_id + self.own_payload
        hdr = Header(MSG_HEARTBEAT, 0x00, self.sender_id, self.sequence,
                     self.timestamp_ms, len(payload))
        pkt = hdr.pack() + payload
        return _pack_hmac(pkt, cluster_key)


def decode_heartbeat(buf: bytes, cluster_key: bytes) -> Heartbeat:
    data = _verify_and_strip_hmac(buf, cluster_key)
    hdr = Header.unpack(data)
    if hdr.msg_type != MSG_HEARTBEAT:
        raise ProtocolError("not a HEARTBEAT")
    if len(data) != HEADER_LEN + hdr.payload_len:
        raise ProtocolError("declared length mismatch")
    if hdr.payload_len < 8 or hdr.payload_len > 8 + NODE_PAYLOAD_MAX:
        raise ProtocolError("heartbeat payload_len out of range")
    payload = data[HEADER_LEN:HEADER_LEN + hdr.payload_len]
    return Heartbeat(
        sender_id=hdr.sender_id,
        sequence=hdr.sequence,
        timestamp_ms=hdr.timestamp_ms,
        query_target_id=payload[:8],
        own_payload=payload[8:],
    )


# ---- STATUS_LIST (0x02) ----


@dataclass(frozen=True)
class ListEntry:
    peer_sender_id: bytes   # 8
    peer_ipv4: bytes        # 4
    last_seen_seconds: int

    def pack(self) -> bytes:
        if len(self.peer_sender_id) != 8 or len(self.peer_ipv4) != 4:
            raise ProtocolError("list entry field sizes")
        return struct.pack(">8s4sI", self.peer_sender_id, self.peer_ipv4,
                           self.last_seen_seconds & 0xFFFFFFFF)

    @classmethod
    def unpack(cls, buf: bytes, off: int) -> "ListEntry":
        if len(buf) - off < LIST_ENTRY_LEN:
            raise ProtocolError("short list entry")
        pid, ip, ls = struct.unpack_from(">8s4sI", buf, off)
        return cls(peer_sender_id=bytes(pid), peer_ipv4=bytes(ip),
                   last_seen_seconds=ls)


@dataclass(frozen=True)
class StatusList:
    sender_id: bytes        # witness's id
    sequence: int
    timestamp_ms: int
    witness_uptime_ms: int
    entries: tuple[ListEntry, ...] = field(default=())

    def encode(self, cluster_key: bytes) -> bytes:
        if len(self.entries) > LIST_MAX_ENTRIES:
            raise ProtocolError("too many list entries")
        body = struct.pack(">QBB", self.witness_uptime_ms,
                           len(self.entries), 0)
        for e in self.entries:
            body += e.pack()
        hdr = Header(MSG_STATUS_LIST, 0x00, self.sender_id, self.sequence,
                     self.timestamp_ms, len(body))
        return _pack_hmac(hdr.pack() + body, cluster_key)


def decode_status_list(buf: bytes, cluster_key: bytes) -> StatusList:
    data = _verify_and_strip_hmac(buf, cluster_key)
    hdr = Header.unpack(data)
    if hdr.msg_type != MSG_STATUS_LIST:
        raise ProtocolError("not a STATUS_LIST")
    if len(data) != HEADER_LEN + hdr.payload_len:
        raise ProtocolError("declared length mismatch")
    body = data[HEADER_LEN:]
    if len(body) < 10:
        raise ProtocolError("status_list body too short")
    up_ms, n, reserved = struct.unpack_from(">QBB", body, 0)
    if reserved != 0:
        raise ProtocolError("reserved byte nonzero")
    if n > LIST_MAX_ENTRIES:
        raise ProtocolError("num_entries too large")
    expected = 10 + n * LIST_ENTRY_LEN
    if len(body) != expected:
        raise ProtocolError(f"status_list body length {len(body)} != {expected}")
    entries = tuple(
        ListEntry.unpack(body, 10 + i * LIST_ENTRY_LEN) for i in range(n)
    )
    return StatusList(
        sender_id=hdr.sender_id, sequence=hdr.sequence,
        timestamp_ms=hdr.timestamp_ms,
        witness_uptime_ms=up_ms, entries=entries,
    )


# ---- STATUS_DETAIL (0x03) ----


@dataclass(frozen=True)
class StatusDetail:
    sender_id: bytes
    sequence: int
    timestamp_ms: int
    witness_uptime_ms: int
    target_sender_id: bytes
    status: int                 # 0x00 found, 0x01 not found
    peer_ipv4: bytes = b"\x00" * 4
    last_seen_seconds: int = 0
    peer_payload: bytes = b""

    def encode(self, cluster_key: bytes) -> bytes:
        if len(self.target_sender_id) != 8:
            raise ProtocolError("target_sender_id must be 8 bytes")
        if self.status not in (0x00, 0x01):
            raise ProtocolError("bad status byte")
        body = struct.pack(">Q8sBB", self.witness_uptime_ms,
                           self.target_sender_id, self.status, 0)
        if self.status == 0x00:
            if len(self.peer_ipv4) != 4:
                raise ProtocolError("peer_ipv4 must be 4 bytes")
            if len(self.peer_payload) > NODE_PAYLOAD_MAX:
                raise ProtocolError("peer_payload too long")
            body += struct.pack(">4sIB", self.peer_ipv4,
                                self.last_seen_seconds & 0xFFFFFFFF,
                                len(self.peer_payload))
            body += self.peer_payload
        hdr = Header(MSG_STATUS_DETAIL, 0x00, self.sender_id, self.sequence,
                     self.timestamp_ms, len(body))
        return _pack_hmac(hdr.pack() + body, cluster_key)


def decode_status_detail(buf: bytes, cluster_key: bytes) -> StatusDetail:
    data = _verify_and_strip_hmac(buf, cluster_key)
    hdr = Header.unpack(data)
    if hdr.msg_type != MSG_STATUS_DETAIL:
        raise ProtocolError("not a STATUS_DETAIL")
    if len(data) != HEADER_LEN + hdr.payload_len:
        raise ProtocolError("declared length mismatch")
    body = data[HEADER_LEN:]
    if len(body) < 18:
        raise ProtocolError("status_detail body too short")
    up_ms, target, status, reserved = struct.unpack_from(">Q8sBB", body, 0)
    if reserved != 0:
        raise ProtocolError("reserved byte nonzero")
    if status == 0x01:
        if len(body) != 18:
            raise ProtocolError("not_found body length must be 18")
        return StatusDetail(
            sender_id=hdr.sender_id, sequence=hdr.sequence,
            timestamp_ms=hdr.timestamp_ms, witness_uptime_ms=up_ms,
            target_sender_id=bytes(target), status=status,
        )
    if status != 0x00:
        raise ProtocolError("bad status byte")
    if len(body) < 27:
        raise ProtocolError("found body too short")
    ipv4, ls, pl_len = struct.unpack_from(">4sIB", body, 18)
    expected = 27 + pl_len
    if len(body) != expected:
        raise ProtocolError(f"found body length {len(body)} != {expected}")
    return StatusDetail(
        sender_id=hdr.sender_id, sequence=hdr.sequence,
        timestamp_ms=hdr.timestamp_ms, witness_uptime_ms=up_ms,
        target_sender_id=bytes(target), status=status,
        peer_ipv4=bytes(ipv4), last_seen_seconds=ls,
        peer_payload=bytes(body[27:27 + pl_len]),
    )


# ---- UNKNOWN_SOURCE (0x10) ----


@dataclass(frozen=True)
class UnknownSource:
    sender_id: bytes
    sequence: int
    timestamp_ms: int

    def encode(self) -> bytes:
        hdr = Header(MSG_UNKNOWN_SOURCE, 0x00, self.sender_id, self.sequence,
                     self.timestamp_ms, 0)
        return hdr.pack()


def decode_unknown_source(buf: bytes) -> UnknownSource:
    hdr = Header.unpack(buf)
    if hdr.msg_type != MSG_UNKNOWN_SOURCE:
        raise ProtocolError("not UNKNOWN_SOURCE")
    if hdr.payload_len != 0 or len(buf) != HEADER_LEN:
        raise ProtocolError("UNKNOWN_SOURCE must have no payload")
    return UnknownSource(sender_id=hdr.sender_id, sequence=hdr.sequence,
                         timestamp_ms=hdr.timestamp_ms)


# ---- BOOTSTRAP (0x20) ----


@dataclass(frozen=True)
class Bootstrap:
    sender_id: bytes
    sequence: int
    timestamp_ms: int
    cluster_key: bytes            # the secret being delivered (32 B)
    init_payload: bytes = b""     # 0..96 bytes

    def encode(self, witness_x25519_pub: bytes, eph_priv: bytes) -> bytes:
        _validate_sender_id(self.sender_id, from_node=True)
        if len(self.cluster_key) != CLUSTER_KEY_LEN:
            raise ProtocolError("cluster_key must be 32 bytes")
        if len(self.init_payload) > BOOTSTRAP_INIT_PAYLOAD_MAX:
            raise ProtocolError("init_payload > 96 bytes")
        if len(eph_priv) != 32 or len(witness_x25519_pub) != 32:
            raise ProtocolError("bad key lengths")
        plaintext = self.cluster_key + self.init_payload
        eph_pub = crypto.x25519_pub_from_priv(eph_priv)
        shared = crypto.x25519_shared(eph_priv, witness_x25519_pub)
        derived = crypto.hkdf_sha256(shared)
        payload_len = EPH_PUBKEY_LEN + len(plaintext) + AEAD_TAG_LEN
        hdr = Header(MSG_BOOTSTRAP, 0x00, self.sender_id, self.sequence,
                     self.timestamp_ms, payload_len)
        hdr_bytes = hdr.pack()
        ciphertext = crypto.aead_encrypt(derived, hdr_bytes, plaintext)
        return hdr_bytes + eph_pub + ciphertext


def decode_bootstrap(buf: bytes, witness_x25519_priv: bytes) -> Bootstrap:
    hdr = Header.unpack(buf)
    if hdr.msg_type != MSG_BOOTSTRAP:
        raise ProtocolError("not a BOOTSTRAP")
    if len(buf) != HEADER_LEN + hdr.payload_len:
        raise ProtocolError("declared length mismatch")
    if hdr.payload_len < EPH_PUBKEY_LEN + CLUSTER_KEY_LEN + AEAD_TAG_LEN:
        raise ProtocolError("bootstrap payload too short")
    pl = buf[HEADER_LEN:HEADER_LEN + hdr.payload_len]
    eph_pub = pl[:EPH_PUBKEY_LEN]
    ciphertext = pl[EPH_PUBKEY_LEN:]
    shared = crypto.x25519_shared(witness_x25519_priv, eph_pub)
    derived = crypto.hkdf_sha256(shared)
    hdr_bytes = buf[:HEADER_LEN]
    try:
        plaintext = crypto.aead_decrypt(derived, hdr_bytes, ciphertext)
    except Exception as e:  # cryptography.exceptions.InvalidTag
        raise AuthError(f"AEAD verification failed: {e}")
    if len(plaintext) < CLUSTER_KEY_LEN:
        raise ProtocolError("decrypted plaintext too short")
    if len(plaintext) > CLUSTER_KEY_LEN + BOOTSTRAP_INIT_PAYLOAD_MAX:
        raise ProtocolError("decrypted plaintext too long")
    return Bootstrap(
        sender_id=hdr.sender_id, sequence=hdr.sequence,
        timestamp_ms=hdr.timestamp_ms,
        cluster_key=plaintext[:CLUSTER_KEY_LEN],
        init_payload=plaintext[CLUSTER_KEY_LEN:],
    )


# ---- BOOTSTRAP_ACK (0x21) ----


@dataclass(frozen=True)
class BootstrapAck:
    sender_id: bytes       # witness sender_id
    sequence: int
    timestamp_ms: int
    status: int            # 0x00 new, 0x01 re-bootstrap same key
    witness_uptime_ms: int

    def encode(self, cluster_key: bytes) -> bytes:
        if self.status not in (0x00, 0x01):
            raise ProtocolError("bad status byte")
        body = struct.pack(">BQ", self.status, self.witness_uptime_ms)
        hdr = Header(MSG_BOOTSTRAP_ACK, 0x00, self.sender_id, self.sequence,
                     self.timestamp_ms, len(body))
        return _pack_hmac(hdr.pack() + body, cluster_key)


def decode_bootstrap_ack(buf: bytes, cluster_key: bytes) -> BootstrapAck:
    data = _verify_and_strip_hmac(buf, cluster_key)
    hdr = Header.unpack(data)
    if hdr.msg_type != MSG_BOOTSTRAP_ACK:
        raise ProtocolError("not a BOOTSTRAP_ACK")
    if len(data) != HEADER_LEN + hdr.payload_len:
        raise ProtocolError("declared length mismatch")
    if hdr.payload_len != 9:
        raise ProtocolError("BOOTSTRAP_ACK payload_len must be 9")
    status, up_ms = struct.unpack_from(">BQ", data, HEADER_LEN)
    if status not in (0x00, 0x01):
        raise ProtocolError("bad status byte")
    return BootstrapAck(
        sender_id=hdr.sender_id, sequence=hdr.sequence,
        timestamp_ms=hdr.timestamp_ms, status=status,
        witness_uptime_ms=up_ms,
    )


# ── Utility ────────────────────────────────────────────────────────────────


def ipv4_to_bytes(s: str) -> bytes:
    return ipaddress.IPv4Address(s).packed


def ipv4_from_bytes(b: bytes) -> str:
    return str(ipaddress.IPv4Address(b))
