//! Constants locked by PROTOCOL.md. Do not change without bumping the
//! protocol identity (different magic + different UDP port).

pub const MAGIC: &[u8; 4] = b"Echo";
pub const HEADER_LEN: usize = 14;
pub const AEAD_TAG_LEN: usize = 16;
pub const MTU_CAP: usize = 1400;

// Message types (PROTOCOL.md §3)
pub const MSG_HEARTBEAT: u8       = 0x01;
pub const MSG_STATUS_LIST: u8     = 0x02;
pub const MSG_STATUS_DETAIL: u8   = 0x03;
pub const MSG_DISCOVER: u8        = 0x04;
pub const MSG_INIT: u8            = 0x10;
pub const MSG_BOOTSTRAP: u8       = 0x20;
pub const MSG_BOOTSTRAP_ACK: u8   = 0x21;

// sender_id reservations
pub const WITNESS_SENDER_ID: u8 = 0xFF;
pub const NODE_SENDER_ID_MAX: u8 = 0xFE;

// Block-granular payload (PROTOCOL.md §4.1)
pub const PAYLOAD_BLOCK_SIZE: usize = 32;
pub const PAYLOAD_MAX_BLOCKS: usize = 36;
pub const PAYLOAD_MAX_BYTES: usize = PAYLOAD_BLOCK_SIZE * PAYLOAD_MAX_BLOCKS; // 1152

// STATUS_LIST entry (PROTOCOL.md §5.2)
pub const LIST_ENTRY_LEN: usize = 5;
pub const LIST_MAX_ENTRIES: usize = 128;

// query_target_id sentinel meaning "give me LIST not DETAIL"
pub const QUERY_LIST_SENTINEL: u8 = 0xFF;

// Crypto field sizes
pub const CLUSTER_KEY_LEN: usize = 32;
pub const EPH_PUBKEY_LEN: usize = 32;
pub const WITNESS_PUBKEY_LEN: usize = 32;

// Anti-spoof cookie (PROTOCOL.md §11.2)
pub const COOKIE_LEN: usize = 16;
pub const WITNESS_COOKIE_SECRET_LEN: usize = 32;

// DISCOVER zero-padding (anti-amp; PROTOCOL.md §1 principle 13, §5.4)
pub const DISCOVER_PAD_LEN: usize = 48;

// Total packet sizes (fixed for these types)
pub const DISCOVER_LEN: usize = HEADER_LEN + DISCOVER_PAD_LEN;                // 62
pub const INIT_LEN: usize = HEADER_LEN + WITNESS_PUBKEY_LEN + COOKIE_LEN;     // 62
pub const BOOTSTRAP_LEN: usize = HEADER_LEN + COOKIE_LEN + EPH_PUBKEY_LEN
    + CLUSTER_KEY_LEN + AEAD_TAG_LEN;                                         // 110
pub const BOOTSTRAP_ACK_PLAINTEXT_LEN: usize = 5; // status + witness_uptime_seconds
pub const BOOTSTRAP_ACK_LEN: usize = HEADER_LEN + BOOTSTRAP_ACK_PLAINTEXT_LEN + AEAD_TAG_LEN; // 35

// STATUS_DETAIL status_and_blocks byte (PROTOCOL.md §5.3)
pub const STATUS_DETAIL_NOT_FOUND_BIT: u8 = 0x80;
pub const STATUS_DETAIL_BLOCKS_MASK: u8 = 0x3F;

// HKDF info string for BOOTSTRAP key derivation (PROTOCOL.md §4.3)
pub const HKDF_INFO: &[u8] = b"bedrock-echo bootstrap";

// BOOTSTRAP nonce is fixed zero (per-packet aead_key uniqueness from
// fresh ephemeral keypair)
pub const BOOTSTRAP_NONCE: [u8; 12] = [0u8; 12];

/// Returns true if msg_type's payload is AEAD-encrypted under cluster_key.
pub fn is_aead_cluster_key_type(msg_type: u8) -> bool {
    matches!(
        msg_type,
        MSG_HEARTBEAT | MSG_STATUS_LIST | MSG_STATUS_DETAIL | MSG_BOOTSTRAP_ACK
    )
}
