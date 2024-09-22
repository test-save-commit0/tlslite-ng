"""PyCrypto RC4 implementation."""
from .cryptomath import *
from .rc4 import *
if pycryptoLoaded:
    import Crypto.Cipher.ARC4


    class PyCrypto_RC4(RC4):

        def __init__(self, key):
            RC4.__init__(self, key, 'pycrypto')
            key = bytes(key)
            self.context = Crypto.Cipher.ARC4.new(key)
