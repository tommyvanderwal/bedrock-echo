//! Fixed 32-byte packet header. See PROTOCOL.md §2.

use crate::constants::*;
use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub msg_type: u8,
    pub reserved: u8,
    pub sender_id: [u8; 8],
    pub sequence: u64,
    pub timestamp_ms: i64,
    pub payload_len: u16,
}

impl Header {
    /// Pack into `out[..32]`. Caller provides a buffer of at least 32 bytes.
    pub fn pack(&self, out: &mut [u8]) {
        assert!(out.len() >= HEADER_LEN);
        out[0..4].copy_from_slice(MAGIC);
        out[4] = self.msg_type;
        out[5] = self.reserved;
        out[6..14].copy_from_slice(&self.sender_id);
        out[14..22].copy_from_slice(&self.sequence.to_be_bytes());
        out[22..30].copy_from_slice(&self.timestamp_ms.to_be_bytes());
        out[30..32].copy_from_slice(&self.payload_len.to_be_bytes());
    }

    /// Parse and validate the 32-byte header. Does NOT check total packet
    /// length against payload_len — callers do that.
    pub fn unpack(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_LEN { return Err(Error::TooShort); }
        if &buf[0..4] != MAGIC { return Err(Error::BadMagic); }
        let msg_type = buf[4];
        if trailer_len(msg_type).is_none() { return Err(Error::BadMsgType); }
        let reserved = buf[5];
        if reserved != 0 { return Err(Error::BadReserved); }
        let mut sender_id = [0u8; 8];
        sender_id.copy_from_slice(&buf[6..14]);
        let sequence = u64::from_be_bytes(buf[14..22].try_into().unwrap());
        let timestamp_ms = i64::from_be_bytes(buf[22..30].try_into().unwrap());
        let payload_len = u16::from_be_bytes(buf[30..32].try_into().unwrap());
        Ok(Header { msg_type, reserved, sender_id, sequence, timestamp_ms, payload_len })
    }

    /// Returns the expected total packet length (`32 + payload_len + trailer`)
    /// assuming the msg_type is valid.
    pub fn expected_total_len(&self) -> Option<usize> {
        trailer_len(self.msg_type).map(|t| HEADER_LEN + self.payload_len as usize + t)
    }
}
