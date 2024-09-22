"""OpenSSL/M2Crypto 3DES implementation."""
from .cryptomath import *
from .tripledes import *
if m2cryptoLoaded:


    class OpenSSL_TripleDES(TripleDES):

        def __init__(self, key, mode, IV):
            TripleDES.__init__(self, key, mode, IV, 'openssl')
            self._IV, self._key = IV, key
            self._context = None
            self._encrypt = None

        def __del__(self):
            if self._context is not None:
                m2.cipher_ctx_free(self._context)
