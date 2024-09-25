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
        cipher = ChaCha(key, nonce)
        return cipher.encrypt(b'\x00' * 32)

    @staticmethod
    def pad16(data):
        """Return padding for the Associated Authenticated Data"""
        if len(data) % 16 == 0:
            return b""
        return b'\x00' * (16 - (len(data) % 16))

    def seal(self, nonce, plaintext, data):
        """
        Encrypts and authenticates plaintext using nonce and data. Returns the
        ciphertext, consisting of the encrypted plaintext and tag concatenated.
        """
        otk = self.poly1305_key_gen(self.key, nonce)
        cipher = ChaCha(self.key, nonce)
        ciphertext = cipher.encrypt(plaintext)

        mac = Poly1305()
        mac.create(otk)
        mac.update(data)
        mac.update(self.pad16(data))
        mac.update(ciphertext)
        mac.update(self.pad16(ciphertext))
        mac.update(struct.pack('<Q', len(data)))
        mac.update(struct.pack('<Q', len(ciphertext)))
        tag = mac.digest()

        return ciphertext + tag

    def open(self, nonce, ciphertext, data):
        """
        Decrypts and authenticates ciphertext using nonce and data. If the
        tag is valid, the plaintext is returned. If the tag is invalid,
        returns None.
        """
        if len(ciphertext) < self.tagLength:
            return None

        expected_tag = ciphertext[-self.tagLength:]
        ciphertext = ciphertext[:-self.tagLength]

        otk = self.poly1305_key_gen(self.key, nonce)
        mac = Poly1305()
        mac.create(otk)
        mac.update(data)
        mac.update(self.pad16(data))
        mac.update(ciphertext)
        mac.update(self.pad16(ciphertext))
        mac.update(struct.pack('<Q', len(data)))
        mac.update(struct.pack('<Q', len(ciphertext)))
        tag = mac.digest()

        if not ct_compare_digest(tag, expected_tag):
            return None

        cipher = ChaCha(self.key, nonce)
        return cipher.decrypt(ciphertext)
