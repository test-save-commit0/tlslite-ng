"""OpenSSL/M2Crypto RC4 implementation."""
from .cryptomath import *
from .rc4 import RC4
if m2cryptoLoaded:


    class OpenSSL_RC4(RC4):

        def __init__(self, key):
            RC4.__init__(self, key, 'openssl')
            self.rc4 = m2.rc4_new()
            m2.rc4_set_key(self.rc4, key)

        def __del__(self):
            m2.rc4_free(self.rc4)
