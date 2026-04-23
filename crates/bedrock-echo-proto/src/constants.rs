//! Constants locked by PROTOCOL.md. Do not change without a version bump.

pub const MAGIC: &[u8; 4] = b"BEW1";
pub const HEADER_LEN: usize = 32;
pub const HMAC_LEN: usize = 32;
pub const MTU_CAP: usize = 1400;

pub const MSG_HEARTBEAT: u8       = 0x01;
pub const MSG_STATUS_LIST: u8     = 0x02;
pub const MSG_STATUS_DETAIL: u8   = 0x03;
pub const MSG_UNKNOWN_SOURCE: u8  = 0x10;
pub const MSG_BOOTSTRAP: u8       = 0x20;
pub const MSG_BOOTSTRAP_ACK: u8   = 0x21;

pub const NODE_PAYLOAD_MAX: usize = 128;
pub const LIST_ENTRY_LEN: usize = 16;
pub const LIST_MAX_ENTRIES: usize = 64;

pub const CLUSTER_KEY_LEN: usize = 32;
pub const EPH_PUBKEY_LEN: usize = 32;
pub const AEAD_TAG_LEN: usize = 16;
pub const BOOTSTRAP_INIT_PAYLOAD_MAX: usize = 96;

pub const HKDF_INFO: &[u8] = b"bedrock-echo v1 bootstrap";

/// Returns the trailer length for a given msg_type, or None for unknown.
pub fn trailer_len(msg_type: u8) -> Option<usize> {
    match msg_type {
        MSG_HEARTBEAT | MSG_STATUS_LIST | MSG_STATUS_DETAIL | MSG_BOOTSTRAP_ACK => Some(HMAC_LEN),
        MSG_UNKNOWN_SOURCE | MSG_BOOTSTRAP => Some(0),
        _ => None,
    }
}

pub fn is_hmac_type(msg_type: u8) -> bool {
    matches!(
        msg_type,
        MSG_HEARTBEAT | MSG_STATUS_LIST | MSG_STATUS_DETAIL | MSG_BOOTSTRAP_ACK
    )
}
