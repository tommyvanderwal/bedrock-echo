"""Bedrock Echo — reference Python implementation.

See PROTOCOL.md for the wire format. This package provides:
- proto:   encode/decode for all message types
- crypto:  small wrappers around X25519 / HKDF / ChaCha20-Poly1305 / HMAC-SHA256
- witness: stateful witness, listening on UDP
- node:    client-side operations a real node performs against a witness
"""
from . import proto, crypto

__all__ = ["proto", "crypto"]
__version__ = "1.0.0"

MAGIC = b"Echo"
DEFAULT_PORT = 12321
MTU_CAP = 1400
HEADER_LEN = 32
HMAC_LEN = 32
