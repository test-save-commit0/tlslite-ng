from __future__ import division
from tlslite.utils import python_aes
from .constanttime import ct_compare_digest
from .cryptomath import bytesToNumber, numberToByteArray


class AESGCM(object):
    """
    AES-GCM implementation. Note: this implementation does not attempt
    to be side-channel resistant. It's also rather slow.
    """

    def __init__(self, key, implementation, rawAesEncrypt):
        self.isBlockCipher = False
        self.isAEAD = True
        self.nonceLength = 12
        self.tagLength = 16
        self.implementation = implementation
        if len(key) == 16:
            self.name = 'aes128gcm'
        elif len(key) == 32:
            self.name = 'aes256gcm'
        else:
            raise AssertionError()
        self.key = key
        self._rawAesEncrypt = rawAesEncrypt
        self._ctr = python_aes.new(self.key, 6, bytearray(b'\x00' * 16))
        h = bytesToNumber(self._rawAesEncrypt(bytearray(16)))
        self._productTable = [0] * 16
        self._productTable[self._reverseBits(1)] = h
        for i in range(2, 16, 2):
            self._productTable[self._reverseBits(i)] = self._gcmShift(self.
                _productTable[self._reverseBits(i // 2)])
            self._productTable[self._reverseBits(i + 1)] = self._gcmAdd(self
                ._productTable[self._reverseBits(i)], h)

    def _mul(self, y):
        """ Returns y*H, where H is the GCM key. """
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
    _gcmReductionTable = [0, 7200, 14400, 9312, 28800, 27808, 18624, 21728,
        57600, 64800, 55616, 50528, 37248, 36256, 43456, 46560]
