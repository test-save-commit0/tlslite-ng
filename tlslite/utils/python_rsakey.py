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
        return self.d != 0

    def acceptsPassword(self):
        """Does it support encrypted key files."""
        return True

    @staticmethod
    def generate(bits, key_type='rsa'):
        """Generate a private key with modulus 'bits' bit big.

        key_type can be "rsa" for a universal rsaEncryption key or
        "rsa-pss" for a key that can be used only for RSASSA-PSS."""
        if key_type not in ('rsa', 'rsa-pss'):
            raise ValueError("key_type must be 'rsa' or 'rsa-pss'")

        def getPrime(bits):
            while True:
                n = getRandomNumber(bits)
                if isPrime(n):
                    return n

        # Generate p and q
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)
        n = p * q

        # Ensure p * q has the correct number of bits
        while n.bit_length() != bits:
            p = getPrime(bits // 2)
            q = getPrime(bits // 2)
            n = p * q

        # Calculate Euler's totient function
        phi = (p - 1) * (q - 1)

        # Choose e
        e = 65537  # Commonly used value for e

        # Calculate d
        d = invMod(e, phi)

        # Calculate additional CRT values
        dP = d % (p - 1)
        dQ = d % (q - 1)
        qInv = invMod(q, p)

        return Python_RSAKey(n, e, d, p, q, dP, dQ, qInv, key_type)

    @staticmethod
    @deprecated_params({'data': 's', 'password_callback': 'passwordCallback'})
    def parsePEM(data, password_callback=None):
        """Parse a string containing a PEM-encoded <privateKey>."""
        from .pem import parsePEM
        from .asn1parser import ASN1Parser

        # Parse the PEM data
        pemType, pemBytes = parsePEM(data, password_callback)

        # Check if it's an RSA private key
        if pemType != "PRIVATE KEY" and pemType != "RSA PRIVATE KEY":
            raise ValueError("Not a valid RSA private key PEM file")

        # Parse the ASN.1 structure
        parser = ASN1Parser(pemBytes)

        # Extract key components
        version = parser.getChild(0).value[0]
        if version != 0:
            raise ValueError("Unsupported RSA private key version")

        n = parser.getChild(1).value
        e = parser.getChild(2).value
        d = parser.getChild(3).value
        p = parser.getChild(4).value
        q = parser.getChild(5).value
        dP = parser.getChild(6).value
        dQ = parser.getChild(7).value
        qInv = parser.getChild(8).value

        # Create and return the RSA key
        return Python_RSAKey(n, e, d, p, q, dP, dQ, qInv)
