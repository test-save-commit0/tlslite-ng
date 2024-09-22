"""Pure Python implementation of ChaCha cipher

Implementation that follows RFC 7539 closely.
"""
from __future__ import division
from .compat import compat26Str
import copy
import struct
try:
    from itertools import izip
except ImportError:
    izip = zip


class ChaCha(object):
    """Pure python implementation of ChaCha cipher"""
    constants = [1634760805, 857760878, 2036477234, 1797285236]

    @staticmethod
    def rotl32(v, c):
        """Rotate left a 32 bit integer v by c bits"""
        pass

    @staticmethod
    def quarter_round(x, a, b, c, d):
        """Perform a ChaCha quarter round"""
        pass
    _round_mixup_box = [(0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7,
        11, 15), (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)]

    @classmethod
    def double_round(cls, x):
        """Perform two rounds of ChaCha cipher"""
        pass

    @staticmethod
    def chacha_block(key, counter, nonce, rounds):
        """Generate a state of a single block"""
        pass

    @staticmethod
    def word_to_bytearray(state):
        """Convert state to little endian bytestream"""
        pass

    @staticmethod
    def _bytearray_to_words(data):
        """Convert a bytearray to array of word sized ints"""
        pass

    def __init__(self, key, nonce, counter=0, rounds=20):
        """Set the initial state for the ChaCha cipher"""
        if len(key) != 32:
            raise ValueError('Key must be 256 bit long')
        if len(nonce) != 12:
            raise ValueError('Nonce must be 96 bit long')
        self.key = []
        self.nonce = []
        self.counter = counter
        self.rounds = rounds
        self.key = ChaCha._bytearray_to_words(key)
        self.nonce = ChaCha._bytearray_to_words(nonce)

    def encrypt(self, plaintext):
        """Encrypt the data"""
        pass

    def decrypt(self, ciphertext):
        """Decrypt the data"""
        pass
