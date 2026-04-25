"""Bedrock Echo wire-format encode/decode.

See PROTOCOL.md for the authoritative spec. Constants and layouts match
that document byte-for-byte. Every function is pure: no I/O, no time.

Wire format summary:
  header (14 B):   magic | msg_type | sender_id | timestamp_ms
  payload:         encrypted (most types) or plaintext (DISCOVER, INIT)
  trailer (16 B):  Poly1305 tag (AEAD types) or absent (unauthenticated types)

Block-granular payload sizing: own_payload, peer_payload are 0..36 blocks
of 32 bytes each, declared by an inline u8 count field where applicable.

Anti-spoof cookie (PROTOCOL.md §11.2): INIT carries a 16-byte cookie
bound to the requester's src_ip; BOOTSTRAP must echo it. The cookie is
plaintext but covered by the BOOTSTRAP AAD.
"""
from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field
from typing import ClassVar

from cryptography.exceptions import InvalidTag

from . import crypto


# ── Wire constants (PROTOCOL.md §2, §3) ────────────────────────────────────

MAGIC = b"Echo"
HEADER_LEN = 14
AEAD_TAG_LEN = 16
MTU_CAP = 1400

# msg_type values
MSG_HEARTBEAT       = 0x01
MSG_STATUS_LIST     = 0x02
MSG_STATUS_DETAIL   = 0x03
MSG_DISCOVER        = 0x04
MSG_INIT            = 0x10
MSG_BOOTSTRAP       = 0x20
MSG_BOOTSTRAP_ACK   = 0x21

ALL_MSG_TYPES = {
    MSG_HEARTBEAT, MSG_STATUS_LIST, MSG_STATUS_DETAIL, MSG_DISCOVER,
    MSG_INIT, MSG_BOOTSTRAP, MSG_BOOTSTRAP_ACK,
}

AEAD_CLUSTER_KEY_TYPES = {
    MSG_HEARTBEAT, MSG_STATUS_LIST, MSG_STATUS_DETAIL, MSG_BOOTSTRAP_ACK,
}

# sender_id reservations
WITNESS_SENDER_ID = 0xFF
NODE_SENDER_ID_MAX = 0xFE

# block granularity for variable payloads
PAYLOAD_BLOCK_SIZE = 32
PAYLOAD_MAX_BLOCKS = 36
PAYLOAD_MAX_BYTES = PAYLOAD_BLOCK_SIZE * PAYLOAD_MAX_BLOCKS  # 1152

# STATUS_LIST entry constraints
LIST_ENTRY_LEN = 5
LIST_MAX_ENTRIES = 128

# query_target_id sentinel meaning "give me LIST not DETAIL"
QUERY_LIST_SENTINEL = 0xFF

# crypto field sizes
CLUSTER_KEY_LEN = 32
EPH_PUBKEY_LEN = 32
WITNESS_PUBKEY_LEN = 32

# anti-spoof cookie (PROTOCOL.md §11.2)
COOKIE_LEN = 16
WITNESS_COOKIE_SECRET_LEN = 32

# DISCOVER zero-padding to make request size == INIT reply size
# (anti-amplification — PROTOCOL.md §1 principle 13, §5.4)
DISCOVER_PAD_LEN = 48

# total packet sizes
DISCOVER_LEN = HEADER_LEN + DISCOVER_PAD_LEN                                 # 62
INIT_LEN = HEADER_LEN + WITNESS_PUBKEY_LEN + COOKIE_LEN                      # 62
BOOTSTRAP_LEN = (HEADER_LEN + COOKIE_LEN + EPH_PUBKEY_LEN
                 + CLUSTER_KEY_LEN + AEAD_TAG_LEN)                           # 110
BOOTSTRAP_ACK_PLAINTEXT_LEN = 5  # status (1) + witness_uptime_seconds (4)
BOOTSTRAP_ACK_LEN = HEADER_LEN + BOOTSTRAP_ACK_PLAINTEXT_LEN + AEAD_TAG_LEN  # 35

# STATUS_DETAIL status_and_blocks byte
STATUS_DETAIL_NOT_FOUND_BIT = 0x80
STATUS_DETAIL_BLOCKS_MASK = 0x3F  # bits 0-5 (bit 6 reserved per spec)


# ── Exceptions ─────────────────────────────────────────────────────────────


class ProtocolError(Exception):
    """Structural / length / magic violation. Caller silently drops."""


class AuthError(Exception):
    """AEAD verification failed (bad key, tampered packet, etc.)."""


# ── Header ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Header:
    """The 14-byte common header.

    Layout:
        offset  size  field
        0       4     magic ("Echo")
        4       1     msg_type
        5       1     sender_id (0x00..0xFE for nodes, 0xFF for witness)
        6       8     timestamp_ms (i64, big-endian)
    """
    msg_type: int
    sender_id: int
    timestamp_ms: int

    _STRUCT: ClassVar[struct.Struct] = struct.Struct(">4sBBq")

    def pack(self) -> bytes:
        return self._STRUCT.pack(
            MAGIC,
            self.msg_type & 0xFF,
            self.sender_id & 0xFF,
            self.timestamp_ms,
        )

    @classmethod
    def unpack(cls, buf: bytes) -> "Header":
        if len(buf) < HEADER_LEN:
            raise ProtocolError(f"short header: {len(buf)} < {HEADER_LEN}")
        magic, mt, sid, ts = cls._STRUCT.unpack_from(buf, 0)
        if magic != MAGIC:
            raise ProtocolError(f"bad magic: {magic!r}")
        if mt not in ALL_MSG_TYPES:
            raise ProtocolError(f"unknown msg_type: {mt:#x}")
        return cls(msg_type=mt, sender_id=sid, timestamp_ms=ts)


# ── Nonce derivation (PROTOCOL.md §4.2) ────────────────────────────────────


def derive_nonce(sender_id: int, timestamp_ms: int) -> bytes:
    """Build the 12-byte ChaCha20-Poly1305 nonce from header fields.

    nonce = sender_id (1 B) || 0x00 0x00 0x00 || timestamp_ms (8 B BE)
    """
    return struct.pack(">B3sq", sender_id & 0xFF, b"\x00\x00\x00", timestamp_ms)


# ── Common header validation helpers ───────────────────────────────────────


def _validate_node_sender_id(sender_id: int) -> None:
    if not (0 <= sender_id <= NODE_SENDER_ID_MAX):
        raise ProtocolError(
            f"node sender_id must be 0x00..0xFE, got {sender_id:#x}"
        )


def _validate_witness_sender_id(sender_id: int) -> None:
    if sender_id != WITNESS_SENDER_ID:
        raise ProtocolError(
            f"witness sender_id must be 0xFF, got {sender_id:#x}"
        )


def _check_blocks(n_blocks: int) -> None:
    if not (0 <= n_blocks <= PAYLOAD_MAX_BLOCKS):
        raise ProtocolError(
            f"block count must be 0..{PAYLOAD_MAX_BLOCKS}, got {n_blocks}"
        )


def _check_payload_size(payload: bytes) -> None:
    if len(payload) % PAYLOAD_BLOCK_SIZE != 0:
        raise ProtocolError(
            f"payload length {len(payload)} not a multiple of "
            f"{PAYLOAD_BLOCK_SIZE} bytes (block-granular)"
        )
    if len(payload) > PAYLOAD_MAX_BYTES:
        raise ProtocolError(
            f"payload {len(payload)} bytes exceeds max {PAYLOAD_MAX_BYTES}"
        )


def _aead_seal(cluster_key: bytes, header: Header, plaintext: bytes) -> bytes:
    """Encrypt plaintext under cluster_key with header as AAD; return
    full packet (header || ciphertext+tag)."""
    if len(cluster_key) != CLUSTER_KEY_LEN:
        raise ProtocolError("cluster_key must be 32 bytes")
    aad = header.pack()
    nonce = derive_nonce(header.sender_id, header.timestamp_ms)
    ct = crypto.aead_encrypt(cluster_key, nonce, aad, plaintext)
    return aad + ct


def _aead_open(cluster_key: bytes, buf: bytes) -> tuple[Header, bytes]:
    """Verify+decrypt a packet under cluster_key. Returns (header, plaintext).
    Raises AuthError on tag mismatch, ProtocolError on structural issues."""
    if len(buf) < HEADER_LEN + AEAD_TAG_LEN:
        raise ProtocolError("packet shorter than header+tag")
    if len(cluster_key) != CLUSTER_KEY_LEN:
        raise ProtocolError("cluster_key must be 32 bytes")
    header = Header.unpack(buf)
    aad = buf[:HEADER_LEN]
    ciphertext = buf[HEADER_LEN:]
    nonce = derive_nonce(header.sender_id, header.timestamp_ms)
    try:
        plaintext = crypto.aead_decrypt(cluster_key, nonce, aad, ciphertext)
    except InvalidTag as e:
        raise AuthError("AEAD tag verification failed") from e
    return header, plaintext


# ── HEARTBEAT (0x01) — node → witness ──────────────────────────────────────


@dataclass(frozen=True)
class Heartbeat:
    sender_id: int
    timestamp_ms: int
    query_target_id: int    # 0x00..0xFE = DETAIL target; 0xFF = LIST request
    own_payload: bytes      # length must be 0..1152 and multiple of 32

    def encode(self, cluster_key: bytes) -> bytes:
        _validate_node_sender_id(self.sender_id)
        if not (0 <= self.query_target_id <= 0xFF):
            raise ProtocolError("query_target_id must be 0..0xFF")
        _check_payload_size(self.own_payload)
        n_blocks = len(self.own_payload) // PAYLOAD_BLOCK_SIZE
        plaintext = struct.pack(">BB", self.query_target_id, n_blocks) + self.own_payload
        header = Header(MSG_HEARTBEAT, self.sender_id, self.timestamp_ms)
        return _aead_seal(cluster_key, header, plaintext)


def decode_heartbeat(buf: bytes, cluster_key: bytes) -> Heartbeat:
    header, pt = _aead_open(cluster_key, buf)
    if header.msg_type != MSG_HEARTBEAT:
        raise ProtocolError("not a HEARTBEAT")
    if len(pt) < 2:
        raise ProtocolError("heartbeat plaintext too short")
    qt, n_blocks = pt[0], pt[1]
    _check_blocks(n_blocks)
    expected_pt = 2 + n_blocks * PAYLOAD_BLOCK_SIZE
    if len(pt) != expected_pt:
        raise ProtocolError(
            f"heartbeat plaintext length {len(pt)} != expected {expected_pt}"
        )
    return Heartbeat(
        sender_id=header.sender_id,
        timestamp_ms=header.timestamp_ms,
        query_target_id=qt,
        own_payload=bytes(pt[2:]),
    )


# ── STATUS_LIST (0x02) — witness → node ───────────────────────────────────


@dataclass(frozen=True)
class ListEntry:
    peer_sender_id: int
    last_seen_ms: int        # u32 ms (0..49 days; 72h cap in practice)

    def pack(self) -> bytes:
        return struct.pack(">BI", self.peer_sender_id & 0xFF,
                           self.last_seen_ms & 0xFFFFFFFF)

    @classmethod
    def unpack(cls, buf: bytes, off: int) -> "ListEntry":
        if len(buf) - off < LIST_ENTRY_LEN:
            raise ProtocolError("short list entry")
        sid, ls = struct.unpack_from(">BI", buf, off)
        return cls(peer_sender_id=sid, last_seen_ms=ls)


@dataclass(frozen=True)
class StatusList:
    timestamp_ms: int                 # witness's outgoing timestamp
    witness_uptime_seconds: int       # u32 sec since witness boot
    entries: tuple[ListEntry, ...] = field(default=())

    def encode(self, cluster_key: bytes) -> bytes:
        if len(self.entries) > LIST_MAX_ENTRIES:
            raise ProtocolError(
                f"too many entries: {len(self.entries)} > {LIST_MAX_ENTRIES}"
            )
        plaintext = struct.pack(">IB", self.witness_uptime_seconds & 0xFFFFFFFF,
                                len(self.entries))
        for e in self.entries:
            plaintext += e.pack()
        header = Header(MSG_STATUS_LIST, WITNESS_SENDER_ID, self.timestamp_ms)
        return _aead_seal(cluster_key, header, plaintext)


def decode_status_list(buf: bytes, cluster_key: bytes) -> StatusList:
    header, pt = _aead_open(cluster_key, buf)
    if header.msg_type != MSG_STATUS_LIST:
        raise ProtocolError("not a STATUS_LIST")
    _validate_witness_sender_id(header.sender_id)
    if len(pt) < 5:
        raise ProtocolError("status_list plaintext too short")
    up_s, n = struct.unpack_from(">IB", pt, 0)
    if n > LIST_MAX_ENTRIES:
        raise ProtocolError(f"num_entries {n} > {LIST_MAX_ENTRIES}")
    expected_pt = 5 + n * LIST_ENTRY_LEN
    if len(pt) != expected_pt:
        raise ProtocolError(
            f"status_list plaintext length {len(pt)} != expected {expected_pt}"
        )
    entries = tuple(
        ListEntry.unpack(pt, 5 + i * LIST_ENTRY_LEN) for i in range(n)
    )
    return StatusList(
        timestamp_ms=header.timestamp_ms,
        witness_uptime_seconds=up_s,
        entries=entries,
    )


# ── STATUS_DETAIL (0x03) — witness → node ─────────────────────────────────


@dataclass(frozen=True)
class StatusDetail:
    timestamp_ms: int                 # witness's outgoing timestamp
    witness_uptime_seconds: int
    target_sender_id: int             # echo of caller's query_target_id
    found: bool
    peer_ipv4: bytes = b"\x00" * 4
    peer_seen_ms_ago: int = 0
    peer_payload: bytes = b""         # length must be 0..1152 and multiple of 32

    def encode(self, cluster_key: bytes) -> bytes:
        if not (0 <= self.target_sender_id <= 0xFF):
            raise ProtocolError("target_sender_id must be 0..0xFF")
        if self.found:
            _check_payload_size(self.peer_payload)
            if len(self.peer_ipv4) != 4:
                raise ProtocolError("peer_ipv4 must be 4 bytes")
            n_blocks = len(self.peer_payload) // PAYLOAD_BLOCK_SIZE
            # status_and_blocks: bit 7 = 0 (found), bit 6 = 0 (reserved),
            # bits 0-5 = block count
            status_byte = n_blocks  # 0..36
            plaintext = (
                struct.pack(">IBB",
                            self.witness_uptime_seconds & 0xFFFFFFFF,
                            self.target_sender_id & 0xFF,
                            status_byte)
                + self.peer_ipv4
                + struct.pack(">I", self.peer_seen_ms_ago & 0xFFFFFFFF)
                + self.peer_payload
            )
        else:
            # not found: bit 7 = 1, other bits 0
            status_byte = 0x80
            plaintext = struct.pack(">IBB",
                                    self.witness_uptime_seconds & 0xFFFFFFFF,
                                    self.target_sender_id & 0xFF,
                                    status_byte)
        header = Header(MSG_STATUS_DETAIL, WITNESS_SENDER_ID, self.timestamp_ms)
        return _aead_seal(cluster_key, header, plaintext)


def decode_status_detail(buf: bytes, cluster_key: bytes) -> StatusDetail:
    header, pt = _aead_open(cluster_key, buf)
    if header.msg_type != MSG_STATUS_DETAIL:
        raise ProtocolError("not a STATUS_DETAIL")
    _validate_witness_sender_id(header.sender_id)
    if len(pt) < 6:
        raise ProtocolError("status_detail plaintext too short")
    up_s, target, sb = struct.unpack_from(">IBB", pt, 0)
    if sb & STATUS_DETAIL_NOT_FOUND_BIT:
        # not found — bits 0-6 are reserved (ignores them)
        if len(pt) != 6:
            raise ProtocolError("not_found plaintext must be exactly 6 bytes")
        return StatusDetail(
            timestamp_ms=header.timestamp_ms,
            witness_uptime_seconds=up_s,
            target_sender_id=target,
            found=False,
        )
    # found — bit 6 is reserved (ignore for forward-compat); bits 0-5 = block count
    n_blocks = sb & STATUS_DETAIL_BLOCKS_MASK
    if n_blocks > PAYLOAD_MAX_BLOCKS:
        raise ProtocolError(f"detail block count {n_blocks} invalid")
    expected_pt = 6 + 4 + 4 + n_blocks * PAYLOAD_BLOCK_SIZE  # +ipv4 +seen_ms +payload
    if len(pt) != expected_pt:
        raise ProtocolError(
            f"status_detail plaintext length {len(pt)} != expected {expected_pt}"
        )
    peer_ipv4 = bytes(pt[6:10])
    (seen_ms,) = struct.unpack_from(">I", pt, 10)
    peer_payload = bytes(pt[14:14 + n_blocks * PAYLOAD_BLOCK_SIZE])
    return StatusDetail(
        timestamp_ms=header.timestamp_ms,
        witness_uptime_seconds=up_s,
        target_sender_id=target,
        found=True,
        peer_ipv4=peer_ipv4,
        peer_seen_ms_ago=seen_ms,
        peer_payload=peer_payload,
    )


# ── DISCOVER (0x04) — node → witness, unauthenticated ─────────────────────


@dataclass(frozen=True)
class Discover:
    sender_id: int       # node's chosen ID; can be any 0x00..0xFE
    timestamp_ms: int    # caller's wall-clock; useful for RTT measurement

    def encode(self) -> bytes:
        _validate_node_sender_id(self.sender_id)
        # 14 B header + 48 B zero padding = 62 B total. The padding makes
        # the request size match the INIT reply size, so DISCOVER cannot
        # be used as a UDP amplifier.
        header = Header(MSG_DISCOVER, self.sender_id, self.timestamp_ms).pack()
        return header + b"\x00" * DISCOVER_PAD_LEN


def decode_discover(buf: bytes) -> Discover:
    if len(buf) != DISCOVER_LEN:
        raise ProtocolError(
            f"DISCOVER must be exactly {DISCOVER_LEN} bytes, got {len(buf)}"
        )
    header = Header.unpack(buf)
    if header.msg_type != MSG_DISCOVER:
        raise ProtocolError("not a DISCOVER")
    _validate_node_sender_id(header.sender_id)
    # Padding bytes 14..62: spec says senders MUST zero, witness MAY check.
    # We don't enforce zero-only here so the witness can be lenient against
    # future forward-compat use; the protocol tests verify zero on encode.
    return Discover(sender_id=header.sender_id, timestamp_ms=header.timestamp_ms)


# ── INIT (0x10) — witness → node, unauthenticated ─────────────────────────


@dataclass(frozen=True)
class Init:
    timestamp_ms: int           # witness's best-effort wall-clock; MAY be 0
    witness_pubkey: bytes       # X25519 public key, 32 bytes
    cookie: bytes               # 16 B, cookie(witness_secret, src_ip), §11.2

    def encode(self) -> bytes:
        if len(self.witness_pubkey) != WITNESS_PUBKEY_LEN:
            raise ProtocolError("witness_pubkey must be 32 bytes")
        if len(self.cookie) != COOKIE_LEN:
            raise ProtocolError(f"cookie must be {COOKIE_LEN} bytes")
        header = Header(MSG_INIT, WITNESS_SENDER_ID, self.timestamp_ms)
        return header.pack() + self.witness_pubkey + self.cookie


def decode_init(buf: bytes) -> Init:
    if len(buf) != INIT_LEN:
        raise ProtocolError(
            f"INIT must be exactly {INIT_LEN} bytes, got {len(buf)}"
        )
    header = Header.unpack(buf)
    if header.msg_type != MSG_INIT:
        raise ProtocolError("not INIT")
    _validate_witness_sender_id(header.sender_id)
    return Init(
        timestamp_ms=header.timestamp_ms,
        witness_pubkey=bytes(buf[HEADER_LEN:HEADER_LEN + WITNESS_PUBKEY_LEN]),
        cookie=bytes(buf[HEADER_LEN + WITNESS_PUBKEY_LEN:INIT_LEN]),
    )


# ── BOOTSTRAP (0x20) — node → witness, AEAD via ECDH ──────────────────────


@dataclass(frozen=True)
class Bootstrap:
    sender_id: int
    timestamp_ms: int
    cluster_key: bytes          # the secret being delivered (32 B)
    cookie: bytes               # 16 B anti-spoof token from prior INIT (§11.2)

    def encode(self, witness_pubkey: bytes, eph_priv: bytes) -> bytes:
        _validate_node_sender_id(self.sender_id)
        if len(self.cluster_key) != CLUSTER_KEY_LEN:
            raise ProtocolError("cluster_key must be 32 bytes")
        if len(self.cookie) != COOKIE_LEN:
            raise ProtocolError(f"cookie must be {COOKIE_LEN} bytes")
        if len(eph_priv) != 32 or len(witness_pubkey) != 32:
            raise ProtocolError("bad key lengths")
        eph_pub = crypto.x25519_pub_from_priv(eph_priv)
        shared = crypto.x25519_shared(eph_priv, witness_pubkey)
        aead_key = crypto.hkdf_sha256(shared)
        header = Header(MSG_BOOTSTRAP, self.sender_id, self.timestamp_ms)
        # AAD = header || cookie (PROTOCOL.md §4.3, §5.6)
        aad = header.pack() + self.cookie
        ct = crypto.aead_encrypt(aead_key, crypto.BOOTSTRAP_AEAD_NONCE, aad,
                                 self.cluster_key)
        return aad + eph_pub + ct


def decode_bootstrap(buf: bytes, witness_priv: bytes) -> Bootstrap:
    if len(buf) != BOOTSTRAP_LEN:
        raise ProtocolError(
            f"BOOTSTRAP must be exactly {BOOTSTRAP_LEN} bytes, got {len(buf)}"
        )
    header = Header.unpack(buf)
    if header.msg_type != MSG_BOOTSTRAP:
        raise ProtocolError("not a BOOTSTRAP")
    _validate_node_sender_id(header.sender_id)
    cookie = bytes(buf[HEADER_LEN:HEADER_LEN + COOKIE_LEN])
    aad_end = HEADER_LEN + COOKIE_LEN  # 30
    eph_pub = bytes(buf[aad_end:aad_end + EPH_PUBKEY_LEN])
    ciphertext = bytes(buf[aad_end + EPH_PUBKEY_LEN:])
    try:
        shared = crypto.x25519_shared(witness_priv, eph_pub)
    except Exception as e:
        # Some libraries raise on small-subgroup elements; treat as auth failure.
        raise AuthError(f"bad ephemeral pubkey: {e}") from e
    aead_key = crypto.hkdf_sha256(shared)
    try:
        plaintext = crypto.aead_decrypt(aead_key, crypto.BOOTSTRAP_AEAD_NONCE,
                                        buf[:aad_end], ciphertext)
    except InvalidTag as e:
        raise AuthError("BOOTSTRAP AEAD tag verification failed") from e
    if len(plaintext) != CLUSTER_KEY_LEN:
        raise ProtocolError(
            f"BOOTSTRAP plaintext must be {CLUSTER_KEY_LEN} bytes, "
            f"got {len(plaintext)}"
        )
    return Bootstrap(
        sender_id=header.sender_id,
        timestamp_ms=header.timestamp_ms,
        cluster_key=plaintext,
        cookie=cookie,
    )


# ── BOOTSTRAP_ACK (0x21) — witness → node ─────────────────────────────────


@dataclass(frozen=True)
class BootstrapAck:
    timestamp_ms: int
    status: int                 # bit 0: 0=new, 1=idempotent re-bootstrap
    witness_uptime_seconds: int

    def encode(self, cluster_key: bytes) -> bytes:
        if not (0 <= self.status <= 0xFF):
            raise ProtocolError("status byte out of range")
        plaintext = struct.pack(">BI",
                                self.status & 0xFF,
                                self.witness_uptime_seconds & 0xFFFFFFFF)
        header = Header(MSG_BOOTSTRAP_ACK, WITNESS_SENDER_ID, self.timestamp_ms)
        return _aead_seal(cluster_key, header, plaintext)


def decode_bootstrap_ack(buf: bytes, cluster_key: bytes) -> BootstrapAck:
    if len(buf) != BOOTSTRAP_ACK_LEN:
        raise ProtocolError(
            f"BOOTSTRAP_ACK must be exactly {BOOTSTRAP_ACK_LEN} bytes, "
            f"got {len(buf)}"
        )
    header, pt = _aead_open(cluster_key, buf)
    if header.msg_type != MSG_BOOTSTRAP_ACK:
        raise ProtocolError("not BOOTSTRAP_ACK")
    _validate_witness_sender_id(header.sender_id)
    if len(pt) != BOOTSTRAP_ACK_PLAINTEXT_LEN:
        raise ProtocolError(
            f"BOOTSTRAP_ACK plaintext must be {BOOTSTRAP_ACK_PLAINTEXT_LEN} bytes"
        )
    status, up_s = struct.unpack(">BI", pt)
    return BootstrapAck(
        timestamp_ms=header.timestamp_ms,
        status=status,
        witness_uptime_seconds=up_s,
    )


# ── Convenience helpers ────────────────────────────────────────────────────


def ipv4_to_bytes(s: str) -> bytes:
    return ipaddress.IPv4Address(s).packed


def ipv4_from_bytes(b: bytes) -> str:
    return str(ipaddress.IPv4Address(b))


def status_is_new(status: int) -> bool:
    """BOOTSTRAP_ACK status: bit 0 = 0 means new entry created."""
    return (status & 0x01) == 0


def status_is_idempotent(status: int) -> bool:
    """BOOTSTRAP_ACK status: bit 0 = 1 means existing entry, idempotent."""
    return (status & 0x01) == 1
