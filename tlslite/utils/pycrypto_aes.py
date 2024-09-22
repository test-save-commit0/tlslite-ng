"""PyCrypto AES implementation."""
from .cryptomath import *
from .aes import *
if pycryptoLoaded:
    import Crypto.Cipher.AES


    class PyCrypto_AES(AES):

        def __init__(self, key, mode, IV):
            AES.__init__(self, key, mode, IV, 'pycrypto')
            key = bytes(key)
            IV = bytes(IV)
            self.context = Crypto.Cipher.AES.new(key, mode, IV)
