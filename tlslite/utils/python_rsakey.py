"""Pure-Python RSA implementation."""
import threading
from .cryptomath import *
from .rsakey import *
from .pem import *
from .deprecations import deprecated_params
if GMPY2_LOADED:
    from gmpy2 import mpz
elif gmpyLoaded:
    from gmpy import mpz


class Python_RSAKey(RSAKey):

    def __init__(self, n=0, e=0, d=0, p=0, q=0, dP=0, dQ=0, qInv=0,
        key_type='rsa'):
        """Initialise key directly from integers.

        see also generate() and parsePEM()."""
        if n and not e or e and not n:
            raise AssertionError()
        if gmpyLoaded or GMPY2_LOADED:
            n = mpz(n)
            e = mpz(e)
            d = mpz(d)
            p = mpz(p)
            q = mpz(q)
            dP = mpz(dP)
            dQ = mpz(dQ)
            qInv = mpz(qInv)
        self.n = n
        self.e = e
        if p and not q or not p and q:
            raise ValueError('p and q must be set or left unset together')
        if not d and p and q:
            t = lcm(p - 1, q - 1)
            d = invMod(e, t)
        self.d = d
        self.p = p
        self.q = q
        if not dP and p:
            dP = d % (p - 1)
        self.dP = dP
        if not dQ and q:
            dQ = d % (q - 1)
        self.dQ = dQ
        if not qInv:
            qInv = invMod(q, p)
        self.qInv = qInv
        self.blinder = 0
        self.unblinder = 0
        self._lock = threading.Lock()
        self.key_type = key_type

    def hasPrivateKey(self):
        """
        Does the key has the associated private key (True) or is it only
        the public part (False).
        """
        pass

    def acceptsPassword(self):
        """Does it support encrypted key files."""
        pass

    @staticmethod
    def generate(bits, key_type='rsa'):
        """Generate a private key with modulus 'bits' bit big.

        key_type can be "rsa" for a universal rsaEncryption key or
        "rsa-pss" for a key that can be used only for RSASSA-PSS."""
        pass

    @staticmethod
    @deprecated_params({'data': 's', 'password_callback': 'passwordCallback'})
    def parsePEM(data, password_callback=None):
        """Parse a string containing a PEM-encoded <privateKey>."""
        pass
