"""Pure-Python AES implementation."""
from .aes import AES
from .rijndael import Rijndael
from .cryptomath import bytesToNumber, numberToByteArray
__all__ = ['new', 'Python_AES']


class Python_AES(AES):

    def __init__(self, key, mode, IV):
        key, IV = bytearray(key), bytearray(IV)
        super(Python_AES, self).__init__(key, mode, IV, 'python')
        self.rijndael = Rijndael(key, 16)
        self.IV = IV


class Python_AES_CTR(AES):

    def __init__(self, key, mode, IV):
        super(Python_AES_CTR, self).__init__(key, mode, IV, 'python')
        self.rijndael = Rijndael(key, 16)
        self.IV = IV
        self._counter_bytes = 16 - len(self.IV)
        self._counter = self.IV + bytearray(b'\x00' * self._counter_bytes)
