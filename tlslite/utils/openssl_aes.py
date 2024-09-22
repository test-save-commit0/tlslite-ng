"""OpenSSL/M2Crypto AES implementation."""
from .cryptomath import *
from .aes import *
from .python_aes import Python_AES_CTR
if m2cryptoLoaded:

    def new(key, mode, IV):
        """
        Try using AES CTR from m2crpyto,
        if it is not available fall back to the
        python implementation.
        """
        pass


    class OpenSSL_AES(AES):

        def __init__(self, key, mode, IV):
            AES.__init__(self, key, mode, IV, 'openssl')
            self._IV, self._key = IV, key
            self._context = None
            self._encrypt = None

        def __del__(self):
            if self._context is not None:
                m2.cipher_ctx_free(self._context)


    class OpenSSL_CTR(AES):

        def __init__(self, key, mode, IV):
            AES.__init__(self, key, mode, IV, 'openssl')
            self._IV = IV
            self.key = key
            self._context = None
            self._encrypt = None
            if len(key) not in (16, 24, 32):
                raise AssertionError()

        def __del__(self):
            if self._context is not None:
                m2.cipher_ctx_free(self._context)
