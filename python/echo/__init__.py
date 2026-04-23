"""Bedrock Echo — reference Python implementation.

See PROTOCOL.md for the wire format. This package provides:
- proto:   encode/decode for all message types
- crypto:  small wrappers around X25519 / HKDF / ChaCha20-Poly1305 / HMAC-SHA256
- witness: stateful witness, listening on UDP
- node:    client-side operations a real node performs against a witness
"""
from . import proto, crypto

__all__ = ["proto", "crypto"]
__version__ = "0.0.1"

MAGIC = b"BEW1"
DEFAULT_PORT = 7337
MTU_CAP = 1400
HEADER_LEN = 32
HMAC_LEN = 32
