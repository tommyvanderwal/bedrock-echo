//! Bedrock Echo protocol — wire format + crypto core.
//!
//! `no_std`-friendly. No dynamic allocation. All encoding/decoding operates
//! on byte slices and fixed-size arrays. State tables live in the caller
//! (witness crate) so this crate remains pure I/O-free logic.
//!
//! See `PROTOCOL.md` in the repo root for the spec. Every constant and byte
//! offset in this crate matches the spec numerically.

#![cfg_attr(not(test), no_std)]

pub mod constants;
pub mod crypto;
pub mod header;
pub mod msg;

pub use constants::*;
pub use header::Header;

/// Errors produced by decoding. Callers should silently drop the packet
/// that caused one (see PROTOCOL.md §12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Packet too short to hold its declared structure
    TooShort,
    /// Total length doesn't match msg_type + payload_len + trailer
    BadLength,
    /// magic != "BEW1"
    BadMagic,
    /// flags != 0
    BadFlags,
    /// unknown msg_type
    BadMsgType,
    /// sender_id == 0 from a node
    ZeroSenderId,
    /// payload_len outside valid range for this msg_type
    BadPayloadLen,
    /// HMAC or AEAD verification failed
    AuthFailed,
    /// Structural field in payload is invalid (reserved != 0, status not {0,1}, ...)
    BadField,
    /// Exceeds MTU cap
    OverMtu,
}

pub type Result<T> = core::result::Result<T, Error>;
