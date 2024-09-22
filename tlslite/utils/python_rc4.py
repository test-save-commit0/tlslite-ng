"""Pure-Python RC4 implementation."""
from .rc4 import RC4
from .cryptomath import *


class Python_RC4(RC4):

    def __init__(self, keyBytes):
        RC4.__init__(self, keyBytes, 'python')
        S = [i for i in range(256)]
        j = 0
        for i in range(256):
            j = (j + S[i] + keyBytes[i % len(keyBytes)]) % 256
            S[i], S[j] = S[j], S[i]
        self.S = S
        self.i = 0
        self.j = 0
