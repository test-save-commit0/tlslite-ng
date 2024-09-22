"""PyCrypto 3DES implementation."""
from .cryptomath import *
from .tripledes import *
if pycryptoLoaded:
    import Crypto.Cipher.DES3


    class PyCrypto_TripleDES(TripleDES):

        def __init__(self, key, mode, IV):
            TripleDES.__init__(self, key, mode, IV, 'pycrypto')
            key = bytes(key)
            IV = bytes(IV)
            self.context = Crypto.Cipher.DES3.new(key, mode, IV)
