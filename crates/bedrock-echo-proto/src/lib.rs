//! Bedrock Echo protocol — wire format + crypto core.
//!
//! `no_std`-friendly. No dynamic allocation. All encoding/decoding operates
//! on byte slices and fixed-size arrays. State tables live in the caller
//! (witness crate); this crate is pure I/O-free logic.
//!
//! See `PROTOCOL.md` in the repo root for the spec. Every constant and byte
//! offset in this crate matches the spec numerically.

#![cfg_attr(not(test), no_std)]

pub mod constants;
pub mod crypto;
pub mod header;
pub mod msg;

pub use constants::*;
pub use header::{derive_nonce, Header};

/// Errors produced by decoding. Callers should silently drop the packet
/// that caused one (see PROTOCOL.md §12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Packet too short to hold its declared structure.
    TooShort,
    /// Total length doesn't match the structure for this msg_type.
    BadLength,
    /// magic != "Echo".
    BadMagic,
    /// Unknown msg_type.
    BadMsgType,
    /// sender_id reserved (0xFF) used by a node-side message.
    BadSenderId,
    /// Block count or other inline length field outside its valid range.
    BadField,
    /// AEAD tag verification failed (wrong key, tampered packet, etc.).
    AuthFailed,
    /// Exceeds MTU cap.
    OverMtu,
    /// `own_payload` / `peer_payload` not a multiple of 32 bytes.
    BadPayloadSize,
}

pub type Result<T> = core::result::Result<T, Error>;
