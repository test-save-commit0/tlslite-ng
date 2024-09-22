"""OpenSSL/M2Crypto RSA implementation."""
from .cryptomath import *
from .rsakey import *
from .python_rsakey import Python_RSAKey
from .compat import compatAscii2Bytes, compat_b2a
if m2cryptoLoaded:
    from M2Crypto.RSA import RSAError


    class OpenSSL_RSAKey(RSAKey):

        def __init__(self, n=0, e=0, key_type='rsa'):
            self.rsa = None
            self._hasPrivateKey = False
            if n and not e or e and not n:
                raise AssertionError()
            if n and e:
                self.rsa = m2.rsa_new()
                m2.rsa_set_n(self.rsa, numberToMPI(n))
                m2.rsa_set_e(self.rsa, numberToMPI(e))
            self.key_type = key_type

        def __del__(self):
            if self.rsa:
                m2.rsa_free(self.rsa)

        def __getattr__(self, name):
            if name == 'e':
                if not self.rsa:
                    return 0
                return mpiToNumber(m2.rsa_get_e(self.rsa))
            elif name == 'n':
                if not self.rsa:
                    return 0
                return mpiToNumber(m2.rsa_get_n(self.rsa))
            else:
                raise AttributeError
