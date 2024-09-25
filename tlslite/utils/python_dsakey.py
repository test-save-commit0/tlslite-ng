"""Pure-Python RSA implementation."""
from ecdsa.der import encode_sequence, encode_integer, remove_sequence, remove_integer
from .cryptomath import getRandomNumber, getRandomPrime, powMod, numBits, bytesToNumber, invMod, secureHash, GMPY2_LOADED, gmpyLoaded
from .compat import compatHMAC
if GMPY2_LOADED:
    from gmpy2 import mpz
elif gmpyLoaded:
    from gmpy import mpz
from .dsakey import DSAKey


class Python_DSAKey(DSAKey):
    """
    Concrete implementaion of DSA object.
    for func docstring see tlslite/dsakey.py
    """

    def __init__(self, p=0, q=0, g=0, x=0, y=0):
        if gmpyLoaded or GMPY2_LOADED:
            p = mpz(p)
            q = mpz(q)
            g = mpz(g)
            x = mpz(x)
            y = mpz(y)
        self.p = p
        self.q = q
        self.g = g
        self.private_key = x
        self.public_key = y
        if self.private_key and not self.public_key:
            self.public_key = powMod(g, self.private_key, p)
        self.key_type = 'dsa'

    def __len__(self):
        return numBits(self.p)

    def sign(self, data, padding=None, hashAlg=None, saltLen=None):
        """
        :type data: bytearray
        :param data: The value which will be signed (generally a binary
            encoding of hash output.

        :type padding: str
        :param padding: Ignored, present for API compatibility with RSA

        :type hashAlg: str
        :param hashAlg: name of hash that was used for calculating the bytes

        :type saltLen: int
        :param saltLen: Ignored, present for API compatibility with RSA
        """
        k = getRandomNumber(1, self.q - 1)
        r = powMod(self.g, k, self.p) % self.q
        k_inv = invMod(k, self.q)
        s = (k_inv * (bytesToNumber(data) + self.private_key * r)) % self.q
        return encode_sequence(encode_integer(r), encode_integer(s))

    def verify(self, signature, hashData, padding=None, hashAlg=None,
        saltLen=None):
        """Verify the passed-in bytes with the signature.

        This verifies a DSA signature on the passed-in data.

        :type signature: bytearray
        :param signature: The signature.

        :type hashData: bytearray
        :param hashData: The value which will be verified.

        :type padding: str
        :param padding: Ignored, present for API compatibility with RSA

        :type hashAlg: str
        :param hashAlg: Ignored, present for API compatibility with RSA

        :type saltLen: str
        :param saltLen: Ignored, present for API compatibility with RSA

        :rtype: bool
        :returns: Whether the signature matches the passed-in data.
        """
        try:
            signature = bytearray(signature)
            r, s = remove_integer(remove_integer(remove_sequence(signature)))
        except ValueError:
            return False

        if r <= 0 or r >= self.q or s <= 0 or s >= self.q:
            return False

        w = invMod(s, self.q)
        u1 = (bytesToNumber(hashData) * w) % self.q
        u2 = (r * w) % self.q
        v = ((powMod(self.g, u1, self.p) * powMod(self.public_key, u2, self.p)) % self.p) % self.q
        return v == r
