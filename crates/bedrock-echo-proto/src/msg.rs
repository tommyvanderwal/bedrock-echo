//! Message encode/decode for all 6 msg_types.
//!
//! Encoders write into caller-supplied buffers (no alloc). Decoders return
//! views/copies into fixed-size structs.

use crate::constants::*;
use crate::crypto;
use crate::header::Header;
use crate::{Error, Result};

// ─── Helpers ────────────────────────────────────────────────────────────────

#[inline]
fn write_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_be_bytes());
}
#[inline]
fn write_u64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_be_bytes());
}
#[inline]
fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(buf[off..off + 4].try_into().unwrap())
}
#[inline]
fn read_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_be_bytes(buf[off..off + 8].try_into().unwrap())
}

fn finalize_with_hmac(buf: &mut [u8], body_len: usize, cluster_key: &[u8]) {
    // body_len is the length of (header + payload); HMAC appended to buf[body_len..body_len+32].
    let tag = crypto::hmac_sha256(cluster_key, &buf[..body_len]);
    buf[body_len..body_len + HMAC_LEN].copy_from_slice(&tag);
}

fn verify_and_strip_hmac<'a>(
    buf: &'a [u8],
    cluster_key: &[u8],
) -> Result<&'a [u8]> {
    if buf.len() < HMAC_LEN { return Err(Error::TooShort); }
    let body_len = buf.len() - HMAC_LEN;
    let (body, tag) = buf.split_at(body_len);
    if !crypto::hmac_verify(cluster_key, body, tag) {
        return Err(Error::AuthFailed);
    }
    Ok(body)
}

// ─── HEARTBEAT (0x01) ──────────────────────────────────────────────────────

/// Encode a HEARTBEAT into `out`. Returns total bytes written.
/// `out.len()` must be at least `HEADER_LEN + 8 + own_payload.len() + HMAC_LEN`.
pub fn encode_heartbeat(
    out: &mut [u8],
    sender_id: [u8; 8],
    sequence: u64,
    timestamp_ms: i64,
    query_target_id: &[u8; 8],
    own_payload: &[u8],
    cluster_key: &[u8],
) -> Result<usize> {
    if sender_id == [0u8; 8] { return Err(Error::ZeroSenderId); }
    if own_payload.len() > NODE_PAYLOAD_MAX { return Err(Error::BadPayloadLen); }
    let payload_len = 8 + own_payload.len();
    let total = HEADER_LEN + payload_len + HMAC_LEN;
    if total > MTU_CAP { return Err(Error::OverMtu); }
    if out.len() < total { return Err(Error::BadLength); }

    let hdr = Header {
        msg_type: MSG_HEARTBEAT, reserved: 0, sender_id,
        sequence, timestamp_ms,
        payload_len: payload_len as u16,
    };
    hdr.pack(&mut out[..HEADER_LEN]);
    out[HEADER_LEN..HEADER_LEN + 8].copy_from_slice(query_target_id);
    out[HEADER_LEN + 8..HEADER_LEN + 8 + own_payload.len()].copy_from_slice(own_payload);
    let body_len = HEADER_LEN + payload_len;
    finalize_with_hmac(out, body_len, cluster_key);
    Ok(total)
}

pub struct HeartbeatView<'a> {
    pub header: Header,
    pub query_target_id: [u8; 8],
    pub own_payload: &'a [u8],
}

pub fn decode_heartbeat<'a>(buf: &'a [u8], cluster_key: &[u8]) -> Result<HeartbeatView<'a>> {
    if buf.len() > MTU_CAP { return Err(Error::OverMtu); }
    let body = verify_and_strip_hmac(buf, cluster_key)?;
    let hdr = Header::unpack(body)?;
    if hdr.msg_type != MSG_HEARTBEAT { return Err(Error::BadMsgType); }
    if body.len() != HEADER_LEN + hdr.payload_len as usize {
        return Err(Error::BadLength);
    }
    if (hdr.payload_len as usize) < 8
        || (hdr.payload_len as usize) > 8 + NODE_PAYLOAD_MAX {
        return Err(Error::BadPayloadLen);
    }
    if hdr.sender_id == [0u8; 8] { return Err(Error::ZeroSenderId); }
    let mut q = [0u8; 8];
    q.copy_from_slice(&body[HEADER_LEN..HEADER_LEN + 8]);
    let own_payload = &body[HEADER_LEN + 8..HEADER_LEN + hdr.payload_len as usize];
    Ok(HeartbeatView { header: hdr, query_target_id: q, own_payload })
}

// ─── STATUS_LIST (0x02) ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListEntry {
    pub peer_sender_id: [u8; 8],
    pub peer_ipv4: [u8; 4],
    pub last_seen_seconds: u32,
}

/// Write a STATUS_LIST packet. Entries come from the caller's storage.
pub fn encode_status_list(
    out: &mut [u8],
    sender_id: [u8; 8],
    sequence: u64,
    timestamp_ms: i64,
    witness_uptime_ms: u64,
    entries: &[ListEntry],
    cluster_key: &[u8],
) -> Result<usize> {
    if entries.len() > LIST_MAX_ENTRIES { return Err(Error::BadPayloadLen); }
    let payload_len = 10 + entries.len() * LIST_ENTRY_LEN;
    let total = HEADER_LEN + payload_len + HMAC_LEN;
    if total > MTU_CAP { return Err(Error::OverMtu); }
    if out.len() < total { return Err(Error::BadLength); }

    let hdr = Header {
        msg_type: MSG_STATUS_LIST, reserved: 0, sender_id,
        sequence, timestamp_ms,
        payload_len: payload_len as u16,
    };
    hdr.pack(&mut out[..HEADER_LEN]);
    let p = HEADER_LEN;
    write_u64(out, p, witness_uptime_ms);
    out[p + 8] = entries.len() as u8;
    out[p + 9] = 0;
    for (i, e) in entries.iter().enumerate() {
        let off = p + 10 + i * LIST_ENTRY_LEN;
        out[off..off + 8].copy_from_slice(&e.peer_sender_id);
        out[off + 8..off + 12].copy_from_slice(&e.peer_ipv4);
        write_u32(out, off + 12, e.last_seen_seconds);
    }
    finalize_with_hmac(out, HEADER_LEN + payload_len, cluster_key);
    Ok(total)
}

pub struct StatusListView<'a> {
    pub header: Header,
    pub witness_uptime_ms: u64,
    pub raw_entries: &'a [u8],
    pub num_entries: u8,
}

impl<'a> StatusListView<'a> {
    pub fn entry(&self, i: usize) -> Option<ListEntry> {
        if i >= self.num_entries as usize { return None; }
        let off = i * LIST_ENTRY_LEN;
        let mut peer_sender_id = [0u8; 8];
        let mut peer_ipv4 = [0u8; 4];
        peer_sender_id.copy_from_slice(&self.raw_entries[off..off + 8]);
        peer_ipv4.copy_from_slice(&self.raw_entries[off + 8..off + 12]);
        let last_seen_seconds = read_u32(self.raw_entries, off + 12);
        Some(ListEntry { peer_sender_id, peer_ipv4, last_seen_seconds })
    }
}

pub fn decode_status_list<'a>(buf: &'a [u8], cluster_key: &[u8]) -> Result<StatusListView<'a>> {
    if buf.len() > MTU_CAP { return Err(Error::OverMtu); }
    let body = verify_and_strip_hmac(buf, cluster_key)?;
    let hdr = Header::unpack(body)?;
    if hdr.msg_type != MSG_STATUS_LIST { return Err(Error::BadMsgType); }
    if body.len() != HEADER_LEN + hdr.payload_len as usize {
        return Err(Error::BadLength);
    }
    let pl = &body[HEADER_LEN..];
    if pl.len() < 10 { return Err(Error::BadPayloadLen); }
    let witness_uptime_ms = read_u64(pl, 0);
    let n = pl[8];
    if pl[9] != 0 { return Err(Error::BadField); }
    let expected = 10usize + n as usize * LIST_ENTRY_LEN;
    if pl.len() != expected { return Err(Error::BadLength); }
    if n as usize > LIST_MAX_ENTRIES { return Err(Error::BadField); }
    Ok(StatusListView {
        header: hdr,
        witness_uptime_ms,
        num_entries: n,
        raw_entries: &pl[10..],
    })
}

// ─── STATUS_DETAIL (0x03) ──────────────────────────────────────────────────

pub struct StatusDetailFound<'a> {
    pub target_sender_id: [u8; 8],
    pub peer_ipv4: [u8; 4],
    pub last_seen_seconds: u32,
    pub peer_payload: &'a [u8],
}

pub fn encode_status_detail_found(
    out: &mut [u8],
    sender_id: [u8; 8],
    sequence: u64,
    timestamp_ms: i64,
    witness_uptime_ms: u64,
    target_sender_id: &[u8; 8],
    peer_ipv4: &[u8; 4],
    last_seen_seconds: u32,
    peer_payload: &[u8],
    cluster_key: &[u8],
) -> Result<usize> {
    if peer_payload.len() > NODE_PAYLOAD_MAX { return Err(Error::BadPayloadLen); }
    let payload_len = 27 + peer_payload.len();
    let total = HEADER_LEN + payload_len + HMAC_LEN;
    if total > MTU_CAP { return Err(Error::OverMtu); }
    if out.len() < total { return Err(Error::BadLength); }
    let hdr = Header {
        msg_type: MSG_STATUS_DETAIL, reserved: 0, sender_id,
        sequence, timestamp_ms, payload_len: payload_len as u16,
    };
    hdr.pack(&mut out[..HEADER_LEN]);
    let p = HEADER_LEN;
    write_u64(out, p, witness_uptime_ms);
    out[p + 8..p + 16].copy_from_slice(target_sender_id);
    out[p + 16] = 0x00;
    out[p + 17] = 0;
    out[p + 18..p + 22].copy_from_slice(peer_ipv4);
    write_u32(out, p + 22, last_seen_seconds);
    out[p + 26] = peer_payload.len() as u8;
    out[p + 27..p + 27 + peer_payload.len()].copy_from_slice(peer_payload);
    finalize_with_hmac(out, HEADER_LEN + payload_len, cluster_key);
    Ok(total)
}

pub fn encode_status_detail_not_found(
    out: &mut [u8],
    sender_id: [u8; 8],
    sequence: u64,
    timestamp_ms: i64,
    witness_uptime_ms: u64,
    target_sender_id: &[u8; 8],
    cluster_key: &[u8],
) -> Result<usize> {
    let payload_len = 18usize;
    let total = HEADER_LEN + payload_len + HMAC_LEN;
    if out.len() < total { return Err(Error::BadLength); }
    let hdr = Header {
        msg_type: MSG_STATUS_DETAIL, reserved: 0, sender_id,
        sequence, timestamp_ms, payload_len: payload_len as u16,
    };
    hdr.pack(&mut out[..HEADER_LEN]);
    let p = HEADER_LEN;
    write_u64(out, p, witness_uptime_ms);
    out[p + 8..p + 16].copy_from_slice(target_sender_id);
    out[p + 16] = 0x01;
    out[p + 17] = 0;
    finalize_with_hmac(out, HEADER_LEN + payload_len, cluster_key);
    Ok(total)
}

#[derive(Debug)]
pub enum StatusDetailView<'a> {
    Found {
        header: Header,
        witness_uptime_ms: u64,
        target_sender_id: [u8; 8],
        peer_ipv4: [u8; 4],
        last_seen_seconds: u32,
        peer_payload: &'a [u8],
    },
    NotFound {
        header: Header,
        witness_uptime_ms: u64,
        target_sender_id: [u8; 8],
    },
}

pub fn decode_status_detail<'a>(buf: &'a [u8], cluster_key: &[u8]) -> Result<StatusDetailView<'a>> {
    if buf.len() > MTU_CAP { return Err(Error::OverMtu); }
    let body = verify_and_strip_hmac(buf, cluster_key)?;
    let hdr = Header::unpack(body)?;
    if hdr.msg_type != MSG_STATUS_DETAIL { return Err(Error::BadMsgType); }
    if body.len() != HEADER_LEN + hdr.payload_len as usize {
        return Err(Error::BadLength);
    }
    let pl = &body[HEADER_LEN..];
    if pl.len() < 18 { return Err(Error::BadPayloadLen); }
    let witness_uptime_ms = read_u64(pl, 0);
    let mut target = [0u8; 8];
    target.copy_from_slice(&pl[8..16]);
    let status = pl[16];
    if pl[17] != 0 { return Err(Error::BadField); }
    match status {
        0x00 => {
            if pl.len() < 27 { return Err(Error::BadPayloadLen); }
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&pl[18..22]);
            let ls = read_u32(pl, 22);
            let pl_len = pl[26] as usize;
            if pl.len() != 27 + pl_len { return Err(Error::BadLength); }
            Ok(StatusDetailView::Found {
                header: hdr,
                witness_uptime_ms,
                target_sender_id: target,
                peer_ipv4: ip,
                last_seen_seconds: ls,
                peer_payload: &pl[27..27 + pl_len],
            })
        }
        0x01 => {
            if pl.len() != 18 { return Err(Error::BadLength); }
            Ok(StatusDetailView::NotFound {
                header: hdr,
                witness_uptime_ms,
                target_sender_id: target,
            })
        }
        _ => Err(Error::BadField),
    }
}

// ─── UNKNOWN_SOURCE (0x10) ─────────────────────────────────────────────────

pub fn encode_unknown_source(
    out: &mut [u8],
    sender_id: [u8; 8],
    sequence: u64,
    timestamp_ms: i64,
) -> Result<usize> {
    if out.len() < HEADER_LEN { return Err(Error::BadLength); }
    let hdr = Header {
        msg_type: MSG_UNKNOWN_SOURCE, reserved: 0, sender_id,
        sequence, timestamp_ms, payload_len: 0,
    };
    hdr.pack(&mut out[..HEADER_LEN]);
    Ok(HEADER_LEN)
}

pub fn decode_unknown_source(buf: &[u8]) -> Result<Header> {
    if buf.len() != HEADER_LEN { return Err(Error::BadLength); }
    let hdr = Header::unpack(buf)?;
    if hdr.msg_type != MSG_UNKNOWN_SOURCE { return Err(Error::BadMsgType); }
    if hdr.payload_len != 0 { return Err(Error::BadPayloadLen); }
    Ok(hdr)
}

// ─── BOOTSTRAP (0x20) ──────────────────────────────────────────────────────

pub fn encode_bootstrap(
    out: &mut [u8],
    sender_id: [u8; 8],
    sequence: u64,
    timestamp_ms: i64,
    witness_pub: &[u8; 32],
    eph_priv: &[u8; 32],
    cluster_key: &[u8; 32],
    init_payload: &[u8],
) -> Result<usize> {
    if sender_id == [0u8; 8] { return Err(Error::ZeroSenderId); }
    if init_payload.len() > BOOTSTRAP_INIT_PAYLOAD_MAX { return Err(Error::BadPayloadLen); }
    let pt_len = 32 + init_payload.len();
    let payload_len = 32 + pt_len + AEAD_TAG_LEN;
    let total = HEADER_LEN + payload_len;
    if total > MTU_CAP { return Err(Error::OverMtu); }
    if out.len() < total { return Err(Error::BadLength); }

    let hdr = Header {
        msg_type: MSG_BOOTSTRAP, reserved: 0, sender_id,
        sequence, timestamp_ms, payload_len: payload_len as u16,
    };
    hdr.pack(&mut out[..HEADER_LEN]);

    // Ephemeral public at payload[0..32]
    let eph_pub = crypto::x25519_pub_from_priv(eph_priv);
    out[HEADER_LEN..HEADER_LEN + 32].copy_from_slice(&eph_pub);

    // Build plaintext, then encrypt
    // Assemble in the output buffer at [HEADER_LEN+32..HEADER_LEN+32+pt_len+tag]
    let mut plaintext = [0u8; 32 + BOOTSTRAP_INIT_PAYLOAD_MAX];
    plaintext[0..32].copy_from_slice(cluster_key);
    plaintext[32..32 + init_payload.len()].copy_from_slice(init_payload);
    let pt = &plaintext[..pt_len];

    let shared = crypto::x25519_shared(eph_priv, witness_pub);
    let mut derived = [0u8; 32];
    crypto::hkdf_sha256(&shared, &mut derived);
    let aad = &out[..HEADER_LEN];
    // Encrypt into out[HEADER_LEN+32..]
    // We need to construct a slice we can mutate; use a fresh buffer then copy.
    let mut ct_buf = [0u8; (32 + BOOTSTRAP_INIT_PAYLOAD_MAX) + AEAD_TAG_LEN];
    crypto::aead_encrypt(&derived, aad, pt, &mut ct_buf[..pt_len + AEAD_TAG_LEN])?;
    out[HEADER_LEN + 32..HEADER_LEN + 32 + pt_len + AEAD_TAG_LEN]
        .copy_from_slice(&ct_buf[..pt_len + AEAD_TAG_LEN]);

    Ok(total)
}

pub struct BootstrapPlaintext {
    pub cluster_key: [u8; 32],
    pub init_payload_len: usize,
    pub init_payload: [u8; BOOTSTRAP_INIT_PAYLOAD_MAX],
}

pub struct BootstrapDecoded {
    pub header: Header,
    pub plaintext: BootstrapPlaintext,
}

pub fn decode_bootstrap(buf: &[u8], witness_priv: &[u8; 32]) -> Result<BootstrapDecoded> {
    if buf.len() > MTU_CAP { return Err(Error::OverMtu); }
    let hdr = Header::unpack(buf)?;
    if hdr.msg_type != MSG_BOOTSTRAP { return Err(Error::BadMsgType); }
    if buf.len() != HEADER_LEN + hdr.payload_len as usize {
        return Err(Error::BadLength);
    }
    let payload_len = hdr.payload_len as usize;
    if payload_len < 32 + 32 + AEAD_TAG_LEN { return Err(Error::BadPayloadLen); }
    if payload_len > 32 + 32 + BOOTSTRAP_INIT_PAYLOAD_MAX + AEAD_TAG_LEN {
        return Err(Error::BadPayloadLen);
    }
    let pl = &buf[HEADER_LEN..HEADER_LEN + payload_len];
    let mut eph_pub = [0u8; 32];
    eph_pub.copy_from_slice(&pl[..32]);
    let ct_len = payload_len - 32;

    // Copy ciphertext into a local mutable buffer so we can decrypt in place.
    let mut work = [0u8; 32 + BOOTSTRAP_INIT_PAYLOAD_MAX + AEAD_TAG_LEN];
    work[..ct_len].copy_from_slice(&pl[32..]);

    let shared = crypto::x25519_shared(witness_priv, &eph_pub);
    let mut derived = [0u8; 32];
    crypto::hkdf_sha256(&shared, &mut derived);
    let aad = &buf[..HEADER_LEN];
    let pt_len = crypto::aead_decrypt(&derived, aad, &mut work[..ct_len])?;
    if pt_len < 32 { return Err(Error::BadPayloadLen); }

    let mut cluster_key = [0u8; 32];
    cluster_key.copy_from_slice(&work[..32]);
    let init_len = pt_len - 32;
    if init_len > BOOTSTRAP_INIT_PAYLOAD_MAX { return Err(Error::BadPayloadLen); }
    let mut init_payload = [0u8; BOOTSTRAP_INIT_PAYLOAD_MAX];
    init_payload[..init_len].copy_from_slice(&work[32..32 + init_len]);

    Ok(BootstrapDecoded {
        header: hdr,
        plaintext: BootstrapPlaintext {
            cluster_key,
            init_payload_len: init_len,
            init_payload,
        },
    })
}

// ─── BOOTSTRAP_ACK (0x21) ─────────────────────────────────────────────────

pub fn encode_bootstrap_ack(
    out: &mut [u8],
    sender_id: [u8; 8],
    sequence: u64,
    timestamp_ms: i64,
    status: u8,
    witness_uptime_ms: u64,
    cluster_key: &[u8],
) -> Result<usize> {
    if status != 0x00 && status != 0x01 { return Err(Error::BadField); }
    let payload_len = 9;
    let total = HEADER_LEN + payload_len + HMAC_LEN;
    if out.len() < total { return Err(Error::BadLength); }
    let hdr = Header {
        msg_type: MSG_BOOTSTRAP_ACK, reserved: 0, sender_id,
        sequence, timestamp_ms, payload_len: payload_len as u16,
    };
    hdr.pack(&mut out[..HEADER_LEN]);
    out[HEADER_LEN] = status;
    write_u64(out, HEADER_LEN + 1, witness_uptime_ms);
    finalize_with_hmac(out, HEADER_LEN + payload_len, cluster_key);
    Ok(total)
}

pub struct BootstrapAckView {
    pub header: Header,
    pub status: u8,
    pub witness_uptime_ms: u64,
}

pub fn decode_bootstrap_ack(buf: &[u8], cluster_key: &[u8]) -> Result<BootstrapAckView> {
    if buf.len() > MTU_CAP { return Err(Error::OverMtu); }
    let body = verify_and_strip_hmac(buf, cluster_key)?;
    let hdr = Header::unpack(body)?;
    if hdr.msg_type != MSG_BOOTSTRAP_ACK { return Err(Error::BadMsgType); }
    if hdr.payload_len != 9 || body.len() != HEADER_LEN + 9 {
        return Err(Error::BadLength);
    }
    let status = body[HEADER_LEN];
    if status != 0x00 && status != 0x01 { return Err(Error::BadField); }
    let witness_uptime_ms = read_u64(body, HEADER_LEN + 1);
    Ok(BootstrapAckView { header: hdr, status, witness_uptime_ms })
}
