//! Thin wrappers around RustCrypto primitives. `no_std`-compatible; all
//! operations take and return byte arrays or slices.

use crate::constants::{AEAD_TAG_LEN, HKDF_INFO};
use crate::{Error, Result};

use hkdf::Hkdf;
use hmac::Mac;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};

pub type HmacSha256 = hmac::Hmac<Sha256>;

/// Compute HMAC-SHA256. Caller supplies a 32-byte output buffer.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut m = <HmacSha256 as Mac>::new_from_slice(key)
        .expect("hmac-sha256 accepts any key length");
    m.update(data);
    let out = m.finalize().into_bytes();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Constant-time HMAC verification.
pub fn hmac_verify(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    if tag.len() != 32 { return false; }
    let computed = hmac_sha256(key, data);
    computed.ct_eq(tag).into()
}

pub fn x25519_pub_from_priv(priv_bytes: &[u8; 32]) -> [u8; 32] {
    let sk = StaticSecret::from(*priv_bytes);
    PublicKey::from(&sk).to_bytes()
}

pub fn x25519_shared(priv_bytes: &[u8; 32], peer_pub: &[u8; 32]) -> [u8; 32] {
    let sk = StaticSecret::from(*priv_bytes);
    let pk = PublicKey::from(*peer_pub);
    sk.diffie_hellman(&pk).to_bytes()
}

/// HKDF-SHA256 with fixed salt (32 zero bytes) and info = "bedrock-echo v1 bootstrap".
pub fn hkdf_sha256(ikm: &[u8], out: &mut [u8; 32]) {
    let salt = [0u8; 32];
    let h = Hkdf::<Sha256>::new(Some(&salt), ikm);
    h.expand(HKDF_INFO, out).expect("32 is <= 8160 bytes");
}

/// Encrypt plaintext with ChaCha20-Poly1305 using zero nonce (safe because
/// `key` is single-use — derived from a fresh ephemeral X25519 key).
///
/// Writes `ciphertext || tag` into `out`. `out.len()` must equal
/// `plaintext.len() + 16`. Returns the total number of bytes written.
pub fn aead_encrypt(
    key: &[u8; 32],
    aad: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize> {
    use chacha20poly1305::{
        aead::{AeadInPlace, KeyInit},
        ChaCha20Poly1305,
    };
    let needed = plaintext.len() + AEAD_TAG_LEN;
    if out.len() < needed {
        return Err(Error::BadLength);
    }
    // Put plaintext at the start of out, then encrypt-in-place.
    out[..plaintext.len()].copy_from_slice(plaintext);
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = [0u8; 12];
    // encrypt_in_place_detached would let us produce the tag separately; we
    // put them contiguously to match the on-wire format.
    let (ct_region, tag_region) = out[..needed].split_at_mut(plaintext.len());
    let tag = cipher
        .encrypt_in_place_detached(&nonce.into(), aad, ct_region)
        .map_err(|_| Error::AuthFailed)?;
    tag_region.copy_from_slice(&tag);
    Ok(needed)
}

/// Decrypt in place. `buf` contains `ciphertext || tag`. On success, the
/// first `buf.len() - 16` bytes of `buf` are the plaintext (tag is zeroed).
/// Returns the plaintext length.
pub fn aead_decrypt(
    key: &[u8; 32],
    aad: &[u8],
    buf: &mut [u8],
) -> Result<usize> {
    use chacha20poly1305::{
        aead::{AeadInPlace, KeyInit},
        ChaCha20Poly1305,
    };
    if buf.len() < AEAD_TAG_LEN {
        return Err(Error::TooShort);
    }
    let pt_len = buf.len() - AEAD_TAG_LEN;
    let (ct_region, tag_region) = buf.split_at_mut(pt_len);
    let mut tag = [0u8; AEAD_TAG_LEN];
    tag.copy_from_slice(tag_region);
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = [0u8; 12];
    cipher
        .decrypt_in_place_detached(&nonce.into(), aad, ct_region, (&tag).into())
        .map_err(|_| Error::AuthFailed)?;
    Ok(pt_len)
}
