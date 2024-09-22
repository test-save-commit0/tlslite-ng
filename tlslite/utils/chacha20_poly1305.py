"""Pure Python implementation of ChaCha20/Poly1305 AEAD cipher

Implementation that follows RFC 7539 and draft-ietf-tls-chacha20-poly1305-00
"""
from __future__ import division
from .constanttime import ct_compare_digest
from .chacha import ChaCha
from .poly1305 import Poly1305
import struct


class CHACHA20_POLY1305(object):
    """Pure python implementation of ChaCha20/Poly1305 AEAD cipher"""

    def __init__(self, key, implementation):
        """Set the initial state for the ChaCha20 AEAD"""
        if len(key) != 32:
            raise ValueError('Key must be 256 bit long')
        if implementation != 'python':
            raise ValueError('Implementations other then python unsupported')
        self.isBlockCipher = False
        self.isAEAD = True
        self.nonceLength = 12
        self.tagLength = 16
        self.implementation = implementation
        self.name = 'chacha20-poly1305'
        self.key = key

    @staticmethod
    def poly1305_key_gen(key, nonce):
        """Generate the key for the Poly1305 authenticator"""
        pass

    @staticmethod
    def pad16(data):
        """Return padding for the Associated Authenticated Data"""
        pass

    def seal(self, nonce, plaintext, data):
        """
        Encrypts and authenticates plaintext using nonce and data. Returns the
        ciphertext, consisting of the encrypted plaintext and tag concatenated.
        """
        pass

    def open(self, nonce, ciphertext, data):
        """
        Decrypts and authenticates ciphertext using nonce and data. If the
        tag is valid, the plaintext is returned. If the tag is invalid,
        returns None.
        """
        pass
