from __future__ import division
from tlslite.utils.cryptomath import numberToByteArray
from tlslite.utils import python_aes


class AESCCM(object):

    def __init__(self, key, implementation, rawAesEncrypt, tag_length=16):
        self.isBlockCipher = False
        self.isAEAD = True
        self.key = key
        self.tagLength = tag_length
        self.nonceLength = 12
        self.implementation = implementation
        if len(self.key) == 16 and self.tagLength == 8:
            self.name = 'aes128ccm_8'
        elif len(self.key) == 16 and self.tagLength == 16:
            self.name = 'aes128ccm'
        elif len(self.key) == 32 and self.tagLength == 8:
            self.name = 'aes256ccm_8'
        else:
            assert len(self.key) == 32 and self.tagLength == 16
            self.name = 'aes256ccm'
        self._ctr = python_aes.new(self.key, 6, bytearray(b'\x00' * 16))
        self._cbc = python_aes.new(self.key, 2, bytearray(b'\x00' * 16))
