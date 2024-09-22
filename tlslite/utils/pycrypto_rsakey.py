"""PyCrypto RSA implementation."""
from __future__ import print_function
import sys
from .cryptomath import *
from .rsakey import *
from .python_rsakey import Python_RSAKey
from .compat import compatLong
if pycryptoLoaded:
    from Crypto.PublicKey import RSA


    class PyCrypto_RSAKey(RSAKey):

        def __init__(self, n=0, e=0, d=0, p=0, q=0, dP=0, dQ=0, qInv=0,
            key_type='rsa'):
            del dP, dQ, qInv
            if not d:
                self.rsa = RSA.construct((compatLong(n), compatLong(e)))
            else:
                self.rsa = RSA.construct((compatLong(n), compatLong(e),
                    compatLong(d), compatLong(p), compatLong(q)))
            self.key_type = key_type

        def __getattr__(self, name):
            return getattr(self.rsa, name)
