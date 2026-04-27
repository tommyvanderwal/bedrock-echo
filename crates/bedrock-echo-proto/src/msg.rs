//! Message encode/decode for all 7 msg_types (Bedrock Echo).
//!
//! Encoders write into caller-supplied buffers (no_std-friendly).
//! Decoders verify AEAD/structure and return parsed views.
//!
//! See PROTOCOL.md §5 for byte layouts.

use crate::constants::*;
use crate::crypto;
use crate::header::{derive_nonce, Header};
use crate::{Error, Result};

// ── shared helpers ────────────────────────────────────────────────────────

#[inline]
fn write_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_be_bytes());
}
#[inline]
fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(buf[off..off + 4].try_into().unwrap())
}

#[inline]
fn validate_node_sender_id(sender_id: u8) -> Result<()> {
    if sender_id > NODE_SENDER_ID_MAX {
        Err(Error::BadSenderId)
    } else {
        Ok(())
    }
}

#[inline]
fn validate_witness_sender_id(sender_id: u8) -> Result<()> {
    if sender_id != WITNESS_SENDER_ID {
        Err(Error::BadSenderId)
    } else {
        Ok(())
    }
}

#[inline]
fn validate_payload_blocks(n_blocks: usize) -> Result<()> {
    if n_blocks > PAYLOAD_MAX_BLOCKS {
        Err(Error::BadField)
    } else {
        Ok(())
    }
}

#[inline]
fn validate_payload_size(payload: &[u8]) -> Result<()> {
    if payload.len() % PAYLOAD_BLOCK_SIZE != 0 {
        return Err(Error::BadPayloadSize);
    }
    if payload.len() > PAYLOAD_MAX_BYTES {
        return Err(Error::BadPayloadSize);
    }
    Ok(())
}

// ── HEARTBEAT (0x01) — node → witness ─────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Heartbeat<'a> {
    pub header: Header,
    pub query_target_id: u8,
    pub own_payload: &'a [u8], // length is multiple of 32, max 1152
}

/// Encode a HEARTBEAT. Returns total bytes written.
pub fn encode_heartbeat(
    out: &mut [u8],
    sender_id: u8,
    timestamp_ms: i64,
    query_target_id: u8,
    own_payload: &[u8],
    cluster_key: &[u8; CLUSTER_KEY_LEN],
) -> Result<usize> {
    validate_node_sender_id(sender_id)?;
    validate_payload_size(own_payload)?;
    let n_blocks = own_payload.len() / PAYLOAD_BLOCK_SIZE;
    validate_payload_blocks(n_blocks)?;

    let pt_len = 2 + own_payload.len();
    let total = HEADER_LEN + pt_len + AEAD_TAG_LEN;
    if total > MTU_CAP {
        return Err(Error::OverMtu);
    }
    if out.len() < total {
        return Err(Error::BadLength);
    }

    let hdr = Header { msg_type: MSG_HEARTBEAT, sender_id, timestamp_ms };
    hdr.pack(&mut out[..HEADER_LEN]);

    // Build plaintext in a stack scratch buffer.
    let mut pt = [0u8; 2 + PAYLOAD_MAX_BYTES];
    pt[0] = query_target_id;
    pt[1] = n_blocks as u8;
    pt[2..2 + own_payload.len()].copy_from_slice(own_payload);

    let aad = &out[..HEADER_LEN];
    // We can't borrow out twice; use a local buffer for the AEAD output.
    let mut ct_buf = [0u8; PAYLOAD_MAX_BYTES + 2 + AEAD_TAG_LEN];
    let nonce = derive_nonce(sender_id, timestamp_ms);
    let n = crypto::aead_encrypt(cluster_key, &nonce, aad, &pt[..pt_len], &mut ct_buf)?;
    out[HEADER_LEN..HEADER_LEN + n].copy_from_slice(&ct_buf[..n]);
    Ok(total)
}

/// Decode a HEARTBEAT. The input buffer is consumed for in-place AEAD decrypt.
/// Returns `(header, query_target_id, own_payload_len)`. The plaintext payload
/// is left at `buf[HEADER_LEN + 2 .. HEADER_LEN + 2 + own_payload_len]`.
pub fn decode_heartbeat_into<'a>(
    buf: &'a mut [u8],
    cluster_key: &[u8; CLUSTER_KEY_LEN],
) -> Result<(Header, u8, &'a [u8])> {
    if buf.len() < HEADER_LEN + 2 + AEAD_TAG_LEN {
        return Err(Error::TooShort);
    }
    let hdr = Header::unpack(buf)?;
    if hdr.msg_type != MSG_HEARTBEAT {
        return Err(Error::BadMsgType);
    }

    let nonce = derive_nonce(hdr.sender_id, hdr.timestamp_ms);
    let (header_part, ct_part) = buf.split_at_mut(HEADER_LEN);
    let pt_len = crypto::aead_decrypt(cluster_key, &nonce, header_part, ct_part)?;
    if pt_len < 2 {
        return Err(Error::BadLength);
    }
    let query_target_id = ct_part[0];
    let n_blocks = ct_part[1] as usize;
    validate_payload_blocks(n_blocks)?;
    let expected = 2 + n_blocks * PAYLOAD_BLOCK_SIZE;
    if pt_len != expected {
        return Err(Error::BadLength);
    }
    Ok((hdr, query_target_id, &ct_part[2..2 + n_blocks * PAYLOAD_BLOCK_SIZE]))
}

// ── STATUS_LIST (0x02) — witness → node ──────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListEntry {
    pub peer_sender_id: u8,
    pub last_seen_ms: u32,
}

/// Encode a STATUS_LIST. Returns total bytes written.
pub fn encode_status_list(
    out: &mut [u8],
    timestamp_ms: i64,
    witness_uptime_seconds: u32,
    entries: &[ListEntry],
    cluster_key: &[u8; CLUSTER_KEY_LEN],
) -> Result<usize> {
    if entries.len() > LIST_MAX_ENTRIES {
        return Err(Error::BadField);
    }
    let pt_len = 5 + entries.len() * LIST_ENTRY_LEN;
    let total = HEADER_LEN + pt_len + AEAD_TAG_LEN;
    if total > MTU_CAP {
        return Err(Error::OverMtu);
    }
    if out.len() < total {
        return Err(Error::BadLength);
    }

    let hdr = Header {
        msg_type: MSG_STATUS_LIST,
        sender_id: WITNESS_SENDER_ID,
        timestamp_ms,
    };
    hdr.pack(&mut out[..HEADER_LEN]);

    let mut pt = [0u8; 5 + LIST_MAX_ENTRIES * LIST_ENTRY_LEN];
    write_u32(&mut pt, 0, witness_uptime_seconds);
    pt[4] = entries.len() as u8;
    let mut off = 5;
    for e in entries.iter() {
        pt[off] = e.peer_sender_id;
        write_u32(&mut pt, off + 1, e.last_seen_ms);
        off += LIST_ENTRY_LEN;
    }

    let aad = &out[..HEADER_LEN];
    let mut ct_buf = [0u8; 5 + LIST_MAX_ENTRIES * LIST_ENTRY_LEN + AEAD_TAG_LEN];
    let nonce = derive_nonce(WITNESS_SENDER_ID, timestamp_ms);
    let n = crypto::aead_encrypt(cluster_key, &nonce, aad, &pt[..pt_len], &mut ct_buf)?;
    out[HEADER_LEN..HEADER_LEN + n].copy_from_slice(&ct_buf[..n]);
    Ok(total)
}

pub struct StatusListReader<'a> {
    pub header: Header,
    pub witness_uptime_seconds: u32,
    pub num_entries: u8,
    pub entries_bytes: &'a [u8], // 5 * num_entries
}

impl<'a> StatusListReader<'a> {
    pub fn entry(&self, i: usize) -> Option<ListEntry> {
        if i >= self.num_entries as usize {
            return None;
        }
        let base = i * LIST_ENTRY_LEN;
        Some(ListEntry {
            peer_sender_id: self.entries_bytes[base],
            last_seen_ms: read_u32(self.entries_bytes, base + 1),
        })
    }
}

pub fn decode_status_list_into<'a>(
    buf: &'a mut [u8],
    cluster_key: &[u8; CLUSTER_KEY_LEN],
) -> Result<StatusListReader<'a>> {
    if buf.len() < HEADER_LEN + 5 + AEAD_TAG_LEN {
        return Err(Error::TooShort);
    }
    let hdr = Header::unpack(buf)?;
    if hdr.msg_type != MSG_STATUS_LIST {
        return Err(Error::BadMsgType);
    }
    validate_witness_sender_id(hdr.sender_id)?;

    let nonce = derive_nonce(hdr.sender_id, hdr.timestamp_ms);
    let (header_part, ct_part) = buf.split_at_mut(HEADER_LEN);
    let pt_len = crypto::aead_decrypt(cluster_key, &nonce, header_part, ct_part)?;
    if pt_len < 5 {
        return Err(Error::BadLength);
    }
    let witness_uptime_seconds = read_u32(ct_part, 0);
    let num_entries = ct_part[4];
    if num_entries as usize > LIST_MAX_ENTRIES {
        return Err(Error::BadField);
    }
    let expected = 5 + (num_entries as usize) * LIST_ENTRY_LEN;
    if pt_len != expected {
        return Err(Error::BadLength);
    }
    Ok(StatusListReader {
        header: hdr,
        witness_uptime_seconds,
        num_entries,
        entries_bytes: &ct_part[5..5 + (num_entries as usize) * LIST_ENTRY_LEN],
    })
}

// ── STATUS_DETAIL (0x03) — witness → node ────────────────────────────────

/// Encode a STATUS_DETAIL "found" reply.
pub fn encode_status_detail_found(
    out: &mut [u8],
    timestamp_ms: i64,
    witness_uptime_seconds: u32,
    target_sender_id: u8,
    peer_ipv4: &[u8; 4],
    peer_seen_ms_ago: u32,
    peer_payload: &[u8],
    cluster_key: &[u8; CLUSTER_KEY_LEN],
) -> Result<usize> {
    validate_payload_size(peer_payload)?;
    let n_blocks = peer_payload.len() / PAYLOAD_BLOCK_SIZE;
    validate_payload_blocks(n_blocks)?;

    let pt_len = 6 + 4 + 4 + peer_payload.len(); // uptime+target+sb+ipv4+seen+payload
    let total = HEADER_LEN + pt_len + AEAD_TAG_LEN;
    if total > MTU_CAP {
        return Err(Error::OverMtu);
    }
    if out.len() < total {
        return Err(Error::BadLength);
    }

    let hdr = Header {
        msg_type: MSG_STATUS_DETAIL,
        sender_id: WITNESS_SENDER_ID,
        timestamp_ms,
    };
    hdr.pack(&mut out[..HEADER_LEN]);

    let mut pt = [0u8; 6 + 4 + 4 + PAYLOAD_MAX_BYTES];
    write_u32(&mut pt, 0, witness_uptime_seconds);
    pt[4] = target_sender_id;
    pt[5] = n_blocks as u8; // status bit 7 = 0 (found), bits 0-5 = blocks
    pt[6..10].copy_from_slice(peer_ipv4);
    write_u32(&mut pt, 10, peer_seen_ms_ago);
    pt[14..14 + peer_payload.len()].copy_from_slice(peer_payload);

    let aad = &out[..HEADER_LEN];
    let mut ct_buf = [0u8; 6 + 4 + 4 + PAYLOAD_MAX_BYTES + AEAD_TAG_LEN];
    let nonce = derive_nonce(WITNESS_SENDER_ID, timestamp_ms);
    let n = crypto::aead_encrypt(cluster_key, &nonce, aad, &pt[..pt_len], &mut ct_buf)?;
    out[HEADER_LEN..HEADER_LEN + n].copy_from_slice(&ct_buf[..n]);
    Ok(total)
}

/// Encode a STATUS_DETAIL "not found" reply.
pub fn encode_status_detail_not_found(
    out: &mut [u8],
    timestamp_ms: i64,
    witness_uptime_seconds: u32,
    target_sender_id: u8,
    cluster_key: &[u8; CLUSTER_KEY_LEN],
) -> Result<usize> {
    let pt_len = 6;
    let total = HEADER_LEN + pt_len + AEAD_TAG_LEN; // 36
    if out.len() < total {
        return Err(Error::BadLength);
    }
    let hdr = Header {
        msg_type: MSG_STATUS_DETAIL,
        sender_id: WITNESS_SENDER_ID,
        timestamp_ms,
    };
    hdr.pack(&mut out[..HEADER_LEN]);

    let mut pt = [0u8; 6];
    write_u32(&mut pt, 0, witness_uptime_seconds);
    pt[4] = target_sender_id;
    pt[5] = STATUS_DETAIL_NOT_FOUND_BIT; // bit 7 = 1, bits 0-6 = 0 

    let aad = &out[..HEADER_LEN];
    let mut ct_buf = [0u8; 6 + AEAD_TAG_LEN];
    let nonce = derive_nonce(WITNESS_SENDER_ID, timestamp_ms);
    let n = crypto::aead_encrypt(cluster_key, &nonce, aad, &pt, &mut ct_buf)?;
    out[HEADER_LEN..HEADER_LEN + n].copy_from_slice(&ct_buf[..n]);
    Ok(total)
}

#[derive(Debug)]
pub struct StatusDetailReader<'a> {
    pub header: Header,
    pub witness_uptime_seconds: u32,
    pub target_sender_id: u8,
    pub found: bool,
    pub peer_ipv4: [u8; 4],
    pub peer_seen_ms_ago: u32,
    pub peer_payload: &'a [u8],
}

pub fn decode_status_detail_into<'a>(
    buf: &'a mut [u8],
    cluster_key: &[u8; CLUSTER_KEY_LEN],
) -> Result<StatusDetailReader<'a>> {
    if buf.len() < HEADER_LEN + 6 + AEAD_TAG_LEN {
        return Err(Error::TooShort);
    }
    let hdr = Header::unpack(buf)?;
    if hdr.msg_type != MSG_STATUS_DETAIL {
        return Err(Error::BadMsgType);
    }
    validate_witness_sender_id(hdr.sender_id)?;

    let nonce = derive_nonce(hdr.sender_id, hdr.timestamp_ms);
    let (header_part, ct_part) = buf.split_at_mut(HEADER_LEN);
    let pt_len = crypto::aead_decrypt(cluster_key, &nonce, header_part, ct_part)?;
    if pt_len < 6 {
        return Err(Error::BadLength);
    }
    let witness_uptime_seconds = read_u32(ct_part, 0);
    let target_sender_id = ct_part[4];
    let sb = ct_part[5];

    if sb & STATUS_DETAIL_NOT_FOUND_BIT != 0 {
        // not found — ignores other bits
        if pt_len != 6 {
            return Err(Error::BadLength);
        }
        return Ok(StatusDetailReader {
            header: hdr,
            witness_uptime_seconds,
            target_sender_id,
            found: false,
            peer_ipv4: [0u8; 4],
            peer_seen_ms_ago: 0,
            peer_payload: &[],
        });
    }
    // found — bit 6 reserved (ignore for v2 fwd-compat); blocks in bits 0-5
    let n_blocks = (sb & STATUS_DETAIL_BLOCKS_MASK) as usize;
    if n_blocks > PAYLOAD_MAX_BLOCKS {
        return Err(Error::BadField);
    }
    let expected = 6 + 4 + 4 + n_blocks * PAYLOAD_BLOCK_SIZE;
    if pt_len != expected {
        return Err(Error::BadLength);
    }
    let mut peer_ipv4 = [0u8; 4];
    peer_ipv4.copy_from_slice(&ct_part[6..10]);
    let peer_seen_ms_ago = read_u32(ct_part, 10);
    let payload_start = 14;
    let payload_end = payload_start + n_blocks * PAYLOAD_BLOCK_SIZE;
    Ok(StatusDetailReader {
        header: hdr,
        witness_uptime_seconds,
        target_sender_id,
        found: true,
        peer_ipv4,
        peer_seen_ms_ago,
        peer_payload: &ct_part[payload_start..payload_end],
    })
}

// ── DISCOVER (0x04) — node → witness, unauthenticated, zero-padded ──────

const CAPS_OFF: usize = HEADER_LEN;                       // 14
const DISCOVER_PAD_OFF: usize = HEADER_LEN + CAPS_LEN;    // 16
const INIT_PUBKEY_OFF: usize = HEADER_LEN + CAPS_LEN;     // 16
const INIT_COOKIE_OFF: usize = INIT_PUBKEY_OFF + WITNESS_PUBKEY_LEN; // 48

#[inline]
fn write_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_be_bytes());
}
#[inline]
fn read_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_be_bytes(buf[off..off + 2].try_into().unwrap())
}

pub fn encode_discover(
    out: &mut [u8],
    sender_id: u8,
    timestamp_ms: i64,
    capability_flags: u16,
) -> Result<usize> {
    validate_node_sender_id(sender_id)?;
    if out.len() < DISCOVER_LEN {
        return Err(Error::BadLength);
    }
    let hdr = Header { msg_type: MSG_DISCOVER, sender_id, timestamp_ms };
    hdr.pack(&mut out[..HEADER_LEN]);
    write_u16(out, CAPS_OFF, capability_flags);
    // Zero-pad bytes 16..64 so request size == INIT reply size (anti-amp).
    for b in &mut out[DISCOVER_PAD_OFF..DISCOVER_LEN] {
        *b = 0;
    }
    Ok(DISCOVER_LEN)
}

pub fn decode_discover(buf: &[u8]) -> Result<(Header, u16)> {
    if buf.len() != DISCOVER_LEN {
        return Err(Error::BadLength);
    }
    let hdr = Header::unpack(buf)?;
    if hdr.msg_type != MSG_DISCOVER {
        return Err(Error::BadMsgType);
    }
    validate_node_sender_id(hdr.sender_id)?;
    let caps = read_u16(buf, CAPS_OFF);
    // Padding bytes [16..64]: senders MUST zero, receivers MUST NOT
    // reject on non-zero (forward-compat extension point per §16.2).
    Ok((hdr, caps))
}

// ── INIT (0x10) — witness → node, unauthenticated ────────────────────────

pub fn encode_init(
    out: &mut [u8],
    timestamp_ms: i64,
    witness_pubkey: &[u8; WITNESS_PUBKEY_LEN],
    cookie: &[u8; COOKIE_LEN],
    capability_flags: u16,
) -> Result<usize> {
    if out.len() < INIT_LEN {
        return Err(Error::BadLength);
    }
    let hdr = Header {
        msg_type: MSG_INIT,
        sender_id: WITNESS_SENDER_ID,
        timestamp_ms,
    };
    hdr.pack(&mut out[..HEADER_LEN]);
    write_u16(out, CAPS_OFF, capability_flags);
    out[INIT_PUBKEY_OFF..INIT_PUBKEY_OFF + WITNESS_PUBKEY_LEN]
        .copy_from_slice(witness_pubkey);
    out[INIT_COOKIE_OFF..INIT_LEN].copy_from_slice(cookie);
    Ok(INIT_LEN)
}

pub struct InitReader<'a> {
    pub header: Header,
    pub witness_pubkey: &'a [u8; WITNESS_PUBKEY_LEN],
    pub cookie: &'a [u8; COOKIE_LEN],
    pub capability_flags: u16,
}

pub fn decode_init(buf: &[u8]) -> Result<InitReader<'_>> {
    if buf.len() != INIT_LEN {
        return Err(Error::BadLength);
    }
    let hdr = Header::unpack(buf)?;
    if hdr.msg_type != MSG_INIT {
        return Err(Error::BadMsgType);
    }
    validate_witness_sender_id(hdr.sender_id)?;
    let caps = read_u16(buf, CAPS_OFF);
    let witness_pubkey: &[u8; WITNESS_PUBKEY_LEN] =
        buf[INIT_PUBKEY_OFF..INIT_PUBKEY_OFF + WITNESS_PUBKEY_LEN]
            .try_into().unwrap();
    let cookie: &[u8; COOKIE_LEN] =
        buf[INIT_COOKIE_OFF..INIT_LEN].try_into().unwrap();
    Ok(InitReader {
        header: hdr,
        witness_pubkey,
        cookie,
        capability_flags: caps,
    })
}

// ── BOOTSTRAP (0x20) — node → witness, AEAD via ECDH ─────────────────────
//
// Layout (PROTOCOL.md §5.6):
//   [0..14]   header (in AAD)
//   [14..30]  cookie (in AAD; PROTOCOL.md §11.2)
//   [30..62]  eph_pubkey (plaintext)
//   [62..94]  encrypted cluster_key
//   [94..110] Poly1305 tag

const BOOTSTRAP_AAD_LEN: usize = HEADER_LEN + COOKIE_LEN; // 30
const BOOTSTRAP_EPH_OFF: usize = BOOTSTRAP_AAD_LEN;       // 30
const BOOTSTRAP_CT_OFF: usize = BOOTSTRAP_EPH_OFF + EPH_PUBKEY_LEN; // 62

pub fn encode_bootstrap(
    out: &mut [u8],
    sender_id: u8,
    timestamp_ms: i64,
    cluster_key: &[u8; CLUSTER_KEY_LEN],
    witness_pubkey: &[u8; WITNESS_PUBKEY_LEN],
    eph_priv: &[u8; 32],
    cookie: &[u8; COOKIE_LEN],
) -> Result<usize> {
    validate_node_sender_id(sender_id)?;
    if out.len() < BOOTSTRAP_LEN {
        return Err(Error::BadLength);
    }
    let eph_pub = crypto::x25519_pub_from_priv(eph_priv);
    let shared = crypto::x25519_shared(eph_priv, witness_pubkey);
    let mut aead_key = [0u8; 32];
    crypto::hkdf_sha256(&shared, &mut aead_key);

    let hdr = Header { msg_type: MSG_BOOTSTRAP, sender_id, timestamp_ms };
    hdr.pack(&mut out[..HEADER_LEN]);
    out[HEADER_LEN..HEADER_LEN + COOKIE_LEN].copy_from_slice(cookie);
    out[BOOTSTRAP_EPH_OFF..BOOTSTRAP_EPH_OFF + EPH_PUBKEY_LEN].copy_from_slice(&eph_pub);

    // AAD = header || cookie (first 30 bytes). Copy out for the AEAD call.
    let mut aad = [0u8; BOOTSTRAP_AAD_LEN];
    aad.copy_from_slice(&out[..BOOTSTRAP_AAD_LEN]);

    let mut ct_buf = [0u8; CLUSTER_KEY_LEN + AEAD_TAG_LEN];
    let n = crypto::aead_encrypt(
        &aead_key,
        &BOOTSTRAP_NONCE,
        &aad,
        cluster_key,
        &mut ct_buf,
    )?;
    out[BOOTSTRAP_CT_OFF..BOOTSTRAP_CT_OFF + n].copy_from_slice(&ct_buf[..n]);
    Ok(BOOTSTRAP_LEN)
}

pub fn decode_bootstrap(
    buf: &mut [u8],
    witness_priv: &[u8; 32],
) -> Result<(Header, [u8; COOKIE_LEN], [u8; CLUSTER_KEY_LEN])> {
    if buf.len() != BOOTSTRAP_LEN {
        return Err(Error::BadLength);
    }
    let hdr = Header::unpack(buf)?;
    if hdr.msg_type != MSG_BOOTSTRAP {
        return Err(Error::BadMsgType);
    }
    validate_node_sender_id(hdr.sender_id)?;

    let mut cookie = [0u8; COOKIE_LEN];
    cookie.copy_from_slice(&buf[HEADER_LEN..HEADER_LEN + COOKIE_LEN]);

    let mut eph_pub = [0u8; EPH_PUBKEY_LEN];
    eph_pub.copy_from_slice(&buf[BOOTSTRAP_EPH_OFF..BOOTSTRAP_EPH_OFF + EPH_PUBKEY_LEN]);
    let shared = crypto::x25519_shared(witness_priv, &eph_pub);
    let mut aead_key = [0u8; 32];
    crypto::hkdf_sha256(&shared, &mut aead_key);

    // AAD = header || cookie (first 30 bytes). Copy out before mutable split.
    let mut aad = [0u8; BOOTSTRAP_AAD_LEN];
    aad.copy_from_slice(&buf[..BOOTSTRAP_AAD_LEN]);

    // Decrypt the ciphertext+tag in place.
    let pt_len = crypto::aead_decrypt(
        &aead_key,
        &BOOTSTRAP_NONCE,
        &aad,
        &mut buf[BOOTSTRAP_CT_OFF..],
    )?;
    if pt_len != CLUSTER_KEY_LEN {
        return Err(Error::BadLength);
    }
    let mut cluster_key = [0u8; CLUSTER_KEY_LEN];
    cluster_key.copy_from_slice(&buf[BOOTSTRAP_CT_OFF..BOOTSTRAP_CT_OFF + CLUSTER_KEY_LEN]);
    Ok((hdr, cookie, cluster_key))
}

// ── BOOTSTRAP_ACK (0x21) — witness → node ────────────────────────────────

pub fn encode_bootstrap_ack(
    out: &mut [u8],
    timestamp_ms: i64,
    status: u8,
    witness_uptime_seconds: u32,
    cluster_key: &[u8; CLUSTER_KEY_LEN],
) -> Result<usize> {
    if out.len() < BOOTSTRAP_ACK_LEN {
        return Err(Error::BadLength);
    }
    let hdr = Header {
        msg_type: MSG_BOOTSTRAP_ACK,
        sender_id: WITNESS_SENDER_ID,
        timestamp_ms,
    };
    hdr.pack(&mut out[..HEADER_LEN]);

    let mut pt = [0u8; BOOTSTRAP_ACK_PLAINTEXT_LEN];
    pt[0] = status;
    write_u32(&mut pt, 1, witness_uptime_seconds);

    let aad = {
        let mut tmp = [0u8; HEADER_LEN];
        tmp.copy_from_slice(&out[..HEADER_LEN]);
        tmp
    };
    let mut ct_buf = [0u8; BOOTSTRAP_ACK_PLAINTEXT_LEN + AEAD_TAG_LEN];
    let nonce = derive_nonce(WITNESS_SENDER_ID, timestamp_ms);
    let n = crypto::aead_encrypt(cluster_key, &nonce, &aad, &pt, &mut ct_buf)?;
    out[HEADER_LEN..HEADER_LEN + n].copy_from_slice(&ct_buf[..n]);
    Ok(BOOTSTRAP_ACK_LEN)
}

#[derive(Debug, Clone, Copy)]
pub struct BootstrapAck {
    pub header: Header,
    pub status: u8,
    pub witness_uptime_seconds: u32,
}

pub fn decode_bootstrap_ack(
    buf: &mut [u8],
    cluster_key: &[u8; CLUSTER_KEY_LEN],
) -> Result<BootstrapAck> {
    if buf.len() != BOOTSTRAP_ACK_LEN {
        return Err(Error::BadLength);
    }
    let hdr = Header::unpack(buf)?;
    if hdr.msg_type != MSG_BOOTSTRAP_ACK {
        return Err(Error::BadMsgType);
    }
    validate_witness_sender_id(hdr.sender_id)?;

    let nonce = derive_nonce(hdr.sender_id, hdr.timestamp_ms);
    let (header_part, ct_part) = buf.split_at_mut(HEADER_LEN);
    let pt_len = crypto::aead_decrypt(cluster_key, &nonce, header_part, ct_part)?;
    if pt_len != BOOTSTRAP_ACK_PLAINTEXT_LEN {
        return Err(Error::BadLength);
    }
    let status = ct_part[0];
    let witness_uptime_seconds = read_u32(ct_part, 1);
    Ok(BootstrapAck { header: hdr, status, witness_uptime_seconds })
}

/// BOOTSTRAP_ACK status helpers (PROTOCOL.md §5.7).
#[inline]
pub fn status_is_new(status: u8) -> bool {
    status & 0x01 == 0
}
#[inline]
pub fn status_is_idempotent(status: u8) -> bool {
    status & 0x01 == 1
}
