"""Crypto primitives used by Bedrock Echo.

Keep this module tiny — one thin layer over `cryptography`. Everything uses
the primitives named in PROTOCOL.md §5:
  - X25519         key agreement
  - HKDF-SHA256    derive AEAD key from ECDH output
  - ChaCha20-Poly1305 AEAD for BOOTSTRAP payload
  - HMAC-SHA256    authentication of steady-state traffic
"""
from __future__ import annotations

import hmac as _hmac
import hashlib
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HKDF_INFO = b"bedrock-echo v1 bootstrap"
HKDF_SALT = b"\x00" * 32
AEAD_NONCE = b"\x00" * 12


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


def aead_encrypt(key: bytes, aad: bytes, plaintext: bytes,
                 nonce: bytes = AEAD_NONCE) -> bytes:
    """Return ciphertext || 16-byte Poly1305 tag."""
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def aead_decrypt(key: bytes, aad: bytes, ciphertext: bytes,
                 nonce: bytes = AEAD_NONCE) -> bytes:
    """Raises cryptography.exceptions.InvalidTag on failure."""
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return _hmac.new(key, data, hashlib.sha256).digest()


def hmac_verify(key: bytes, data: bytes, tag: bytes) -> bool:
    return _hmac.compare_digest(hmac_sha256(key, data), tag)


def random_bytes(n: int) -> bytes:
    return os.urandom(n)
