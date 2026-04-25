//! Fixed 14-byte packet header (PROTOCOL.md §2) + AEAD nonce derivation.

use crate::constants::*;
use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub msg_type: u8,
    pub sender_id: u8,
    pub timestamp_ms: i64,
}

impl Header {
    /// Pack into `out[..14]`. Caller provides a buffer of at least 14 bytes.
    pub fn pack(&self, out: &mut [u8]) {
        assert!(out.len() >= HEADER_LEN);
        out[0..4].copy_from_slice(MAGIC);
        out[4] = self.msg_type;
        out[5] = self.sender_id;
        out[6..14].copy_from_slice(&self.timestamp_ms.to_be_bytes());
    }

    /// Parse and validate the 14-byte header. Does NOT check total packet
    /// length against payload structure — callers do that.
    pub fn unpack(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_LEN {
            return Err(Error::TooShort);
        }
        if &buf[0..4] != MAGIC {
            return Err(Error::BadMagic);
        }
        let msg_type = buf[4];
        if !is_known_msg_type(msg_type) {
            return Err(Error::BadMsgType);
        }
        let sender_id = buf[5];
        let timestamp_ms = i64::from_be_bytes(buf[6..14].try_into().unwrap());
        Ok(Header {
            msg_type,
            sender_id,
            timestamp_ms,
        })
    }
}

/// Derive the 12-byte ChaCha20-Poly1305 nonce from header fields
/// (PROTOCOL.md §4.2):
///
/// `nonce = sender_id (1 B) || 0x00 0x00 0x00 || timestamp_ms (8 B BE)`
pub fn derive_nonce(sender_id: u8, timestamp_ms: i64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[0] = sender_id;
    // n[1..4] = 0x00 0x00 0x00 (already zero-initialised)
    n[4..12].copy_from_slice(&timestamp_ms.to_be_bytes());
    n
}

fn is_known_msg_type(t: u8) -> bool {
    matches!(
        t,
        MSG_HEARTBEAT
            | MSG_STATUS_LIST
            | MSG_STATUS_DETAIL
            | MSG_DISCOVER
            | MSG_INIT
            | MSG_BOOTSTRAP
            | MSG_BOOTSTRAP_ACK
    )
}
