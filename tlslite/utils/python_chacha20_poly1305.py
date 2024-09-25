"""Pure-Python ChaCha20/Poly1305 implementation."""
from .chacha20_poly1305 import CHACHA20_POLY1305


def new(key):
    """Return an AEAD cipher implementation"""
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes long")
    return CHACHA20_POLY1305(key)
