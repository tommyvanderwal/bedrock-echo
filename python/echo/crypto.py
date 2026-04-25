"""Crypto primitives used by Bedrock Echo.

Three primitives, all common-denominator across languages:
  - X25519              key agreement (BOOTSTRAP)
  - HKDF-SHA256         derive AEAD key from ECDH output (BOOTSTRAP)
  - ChaCha20-Poly1305   AEAD on every authenticated message

HMAC-SHA256 has been removed — AEAD's Poly1305 tag provides
integrity for all authenticated messages, so the HMAC trailer is no
longer needed.
"""
from __future__ import annotations

import os

import hashlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# HKDF parameters for BOOTSTRAP key derivation (PROTOCOL.md §4.3).
HKDF_INFO = b"bedrock-echo bootstrap"
HKDF_SALT = b"\x00" * 32

# BOOTSTRAP uses a fixed zero nonce — safe because aead_key is unique
# per packet (derived from a fresh ephemeral keypair).
BOOTSTRAP_AEAD_NONCE = b"\x00" * 12


def x25519_generate() -> tuple[bytes, bytes]:
    """Return (priv_bytes, pub_bytes), each 32 bytes."""
    sk = X25519PrivateKey.generate()
    return (
        sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
    )


def x25519_pub_from_priv(priv: bytes) -> bytes:
    sk = X25519PrivateKey.from_private_bytes(priv)
    return sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def x25519_shared(priv: bytes, peer_pub: bytes) -> bytes:
    """Compute the X25519 ECDH shared secret.

    Per RFC 7748, all-zero shared secrets indicate the peer used a
    small-subgroup point. The cryptography library raises in that case.
    """
    sk = X25519PrivateKey.from_private_bytes(priv)
    pk = X25519PublicKey.from_public_bytes(peer_pub)
    return sk.exchange(pk)


def hkdf_sha256(ikm: bytes, length: int = 32,
                salt: bytes = HKDF_SALT, info: bytes = HKDF_INFO) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


def aead_encrypt(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
    """ChaCha20-Poly1305 encrypt. Returns ciphertext || 16-byte tag."""
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def aead_decrypt(key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    """ChaCha20-Poly1305 decrypt + verify. Raises InvalidTag on failure."""
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)


def random_bytes(n: int) -> bytes:
    return os.urandom(n)


def derive_cookie(witness_cookie_secret: bytes, src_ip_be: bytes) -> bytes:
    """Anti-spoof cookie (PROTOCOL.md §11.2):

        cookie = SHA-256(witness_cookie_secret || src_ip_be)[:16]

    The witness emits this in INIT and validates it on BOOTSTRAP. The
    cookie is not secret — it is a short MAC over src_ip under a
    witness-only key, used to prove the bootstrapper can receive
    packets at the IP they're claiming.

    src_ip_be is 4 bytes for IPv4 in network byte order. (BOOTSTRAP is
    IPv4-only.)
    """
    if len(witness_cookie_secret) != 32:
        raise ValueError("witness_cookie_secret must be 32 bytes")
    if len(src_ip_be) != 4:
        raise ValueError("src_ip_be must be 4 bytes (IPv4)")
    return hashlib.sha256(witness_cookie_secret + src_ip_be).digest()[:16]
