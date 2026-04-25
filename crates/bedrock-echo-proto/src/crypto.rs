//! Crypto primitives used by Bedrock Echo v1.
//!
//! Three primitives, all common-denominator:
//!   - X25519              key agreement (BOOTSTRAP)
//!   - HKDF-SHA256         derive AEAD key from ECDH output (BOOTSTRAP)
//!   - ChaCha20-Poly1305   AEAD on every authenticated message
//!
//! HMAC-SHA256 has been removed in v1 — Poly1305 (built into AEAD)
//! provides integrity for all authenticated messages.

use crate::constants::{AEAD_TAG_LEN, COOKIE_LEN, HKDF_INFO};
use crate::{Error, Result};

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

/// Derive the public X25519 key from a private key.
pub fn x25519_pub_from_priv(priv_bytes: &[u8; 32]) -> [u8; 32] {
    let sk = StaticSecret::from(*priv_bytes);
    PublicKey::from(&sk).to_bytes()
}

/// Compute the X25519 ECDH shared secret.
pub fn x25519_shared(priv_bytes: &[u8; 32], peer_pub: &[u8; 32]) -> [u8; 32] {
    let sk = StaticSecret::from(*priv_bytes);
    let pk = PublicKey::from(*peer_pub);
    sk.diffie_hellman(&pk).to_bytes()
}

/// HKDF-SHA256 with fixed salt (32 zero bytes) and info = `b"bedrock-echo bootstrap"`.
pub fn hkdf_sha256(ikm: &[u8], out: &mut [u8; 32]) {
    let salt = [0u8; 32];
    let h = Hkdf::<Sha256>::new(Some(&salt), ikm);
    h.expand(HKDF_INFO, out).expect("32 is <= 8160 bytes");
}

/// Anti-spoof cookie (PROTOCOL.md §11.2):
///   `cookie = SHA-256(witness_cookie_secret || src_ip_be)[:16]`
///
/// The witness emits this in INIT and validates it on BOOTSTRAP.
/// `src_ip_be` is 4 bytes for IPv4 in network byte order. (BOOTSTRAP
/// is IPv4-only in v1.)
pub fn derive_cookie(witness_cookie_secret: &[u8; 32], src_ip_be: &[u8; 4]) -> [u8; COOKIE_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(witness_cookie_secret);
    hasher.update(src_ip_be);
    let digest = hasher.finalize();
    let mut out = [0u8; COOKIE_LEN];
    out.copy_from_slice(&digest[..COOKIE_LEN]);
    out
}

/// Encrypt with ChaCha20-Poly1305. Writes `ciphertext || tag` into `out`.
/// `out.len()` must be at least `plaintext.len() + 16`. Returns total
/// bytes written.
pub fn aead_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize> {
    use chacha20poly1305::{aead::AeadInPlace, ChaCha20Poly1305, KeyInit};
    let needed = plaintext.len() + AEAD_TAG_LEN;
    if out.len() < needed {
        return Err(Error::BadLength);
    }
    out[..plaintext.len()].copy_from_slice(plaintext);
    let cipher = ChaCha20Poly1305::new(key.into());
    let (ct_region, tag_region) = out[..needed].split_at_mut(plaintext.len());
    let tag = cipher
        .encrypt_in_place_detached(nonce.into(), aad, ct_region)
        .map_err(|_| Error::AuthFailed)?;
    tag_region.copy_from_slice(&tag);
    Ok(needed)
}

/// Decrypt-in-place. `buf` contains `ciphertext || tag`. On success the
/// first `buf.len() - 16` bytes of `buf` are the plaintext.
/// Returns the plaintext length on success.
pub fn aead_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
) -> Result<usize> {
    use chacha20poly1305::{aead::AeadInPlace, ChaCha20Poly1305, KeyInit};
    if buf.len() < AEAD_TAG_LEN {
        return Err(Error::TooShort);
    }
    let pt_len = buf.len() - AEAD_TAG_LEN;
    let (ct_region, tag_region) = buf.split_at_mut(pt_len);
    let mut tag = [0u8; AEAD_TAG_LEN];
    tag.copy_from_slice(tag_region);
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt_in_place_detached(nonce.into(), aad, ct_region, (&tag).into())
        .map_err(|_| Error::AuthFailed)?;
    Ok(pt_len)
}
