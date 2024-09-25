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
        try:
            return OpenSSL_CTR(key, mode, IV)
        except:
            return Python_AES_CTR(key, mode, IV)


    class OpenSSL_AES(AES):

        def __init__(self, key, mode, IV):
            AES.__init__(self, key, mode, IV, 'openssl')
            self._IV, self._key = IV, key
            self._context = m2.cipher_ctx_new()
            self._encrypt = None
            if mode == 2:  # CBC mode
                alg = m2.aes_128_cbc()
            else:
                raise ValueError("Unsupported AES mode")
            m2.cipher_init(self._context, alg, key, IV, 1)  # 1 for encryption

        def __del__(self):
            if self._context is not None:
                m2.cipher_ctx_free(self._context)

        def encrypt(self, plaintext):
            return m2.cipher_update(self._context, plaintext)

        def decrypt(self, ciphertext):
            m2.cipher_ctx_free(self._context)
            self._context = m2.cipher_ctx_new()
            if self.mode == 2:  # CBC mode
                alg = m2.aes_128_cbc()
            else:
                raise ValueError("Unsupported AES mode")
            m2.cipher_init(self._context, alg, self._key, self._IV, 0)  # 0 for decryption
            return m2.cipher_update(self._context, ciphertext)


    class OpenSSL_CTR(AES):

        def __init__(self, key, mode, IV):
            AES.__init__(self, key, mode, IV, 'openssl')
            self._IV = IV
            self.key = key
            self._context = m2.cipher_ctx_new()
            self._encrypt = None
            if len(key) not in (16, 24, 32):
                raise AssertionError()
            alg = m2.aes_128_ctr()
            m2.cipher_init(self._context, alg, key, IV, 1)  # 1 for encryption (CTR mode is symmetric)

        def __del__(self):
            if self._context is not None:
                m2.cipher_ctx_free(self._context)

        def encrypt(self, plaintext):
            return m2.cipher_update(self._context, plaintext)

        def decrypt(self, ciphertext):
            return m2.cipher_update(self._context, ciphertext)
