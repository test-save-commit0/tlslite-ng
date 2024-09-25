"""cryptomath module

This module has basic math/crypto code."""
from __future__ import print_function
import os
import math
import base64
import binascii
from .compat import compat26Str, compatHMAC, compatLong, bytes_to_int, int_to_bytes, bit_length, byte_length
from .codec import Writer
from . import tlshashlib as hashlib
from . import tlshmac as hmac
try:
    from M2Crypto import m2
    m2cryptoLoaded = True
    M2CRYPTO_AES_CTR = False
    if hasattr(m2, 'aes_192_ctr'):
        M2CRYPTO_AES_CTR = True
    try:
        with open('/proc/sys/crypto/fips_enabled', 'r') as fipsFile:
            if '1' in fipsFile.read():
                m2cryptoLoaded = False
    except (IOError, OSError):
        m2cryptoLoaded = True
    if not hasattr(m2, 'aes_192_cbc'):
        m2cryptoLoaded = False
except ImportError:
    m2cryptoLoaded = False
try:
    import gmpy
    gmpy.mpz
    gmpyLoaded = True
except ImportError:
    gmpyLoaded = False
try:
    from gmpy2 import powmod
    GMPY2_LOADED = True
except ImportError:
    GMPY2_LOADED = False
if GMPY2_LOADED:
    from gmpy2 import mpz
elif gmpyLoaded:
    from gmpy import mpz
try:
    import Crypto.Cipher.AES
    try:
        Crypto.Cipher.AES.AESCipher(b'2' * (128 // 8))
        pycryptoLoaded = True
    except AttributeError:
        pycryptoLoaded = False
except ImportError:
    pycryptoLoaded = False
import zlib
assert len(zlib.compress(os.urandom(1000))) > 900
prngName = 'os.urandom'


def MD5(b):
    """Return a MD5 digest of data"""
    return hashlib.md5(b).digest()


def SHA1(b):
    """Return a SHA1 digest of data"""
    return hashlib.sha1(b).digest()


def secureHash(data, algorithm):
    """Return a digest of `data` using `algorithm`"""
    return hashlib.new(algorithm, data).digest()


def secureHMAC(k, b, algorithm):
    """Return a HMAC using `b` and `k` using `algorithm`"""
    return hmac.new(k, b, algorithm).digest()


def HKDF_expand_label(secret, label, hashValue, length, algorithm):
    """
    TLS1.3 key derivation function (HKDF-Expand-Label).

    :param bytearray secret: the key from which to derive the keying material
    :param bytearray label: label used to differentiate the keying materials
    :param bytearray hashValue: bytes used to "salt" the produced keying
        material
    :param int length: number of bytes to produce
    :param str algorithm: name of the secure hash algorithm used as the
        basis of the HKDF
    :rtype: bytearray
    """
    hkdf = hmac.new(secret, digestmod=algorithm)
    info = Writer().add(numberToByteArray(length, 2), bytearray(b"tls13 "), label, hashValue).bytes()
    return bytearray(hkdf.derive(info, length))


def derive_secret(secret, label, handshake_hashes, algorithm):
    """
    TLS1.3 key derivation function (Derive-Secret).

    :param bytearray secret: secret key used to derive the keying material
    :param bytearray label: label used to differentiate they keying materials
    :param HandshakeHashes handshake_hashes: hashes of the handshake messages
        or `None` if no handshake transcript is to be used for derivation of
        keying material
    :param str algorithm: name of the secure hash algorithm used as the
        basis of the HKDF algorithm - governs how much keying material will
        be generated
    :rtype: bytearray
    """
    if handshake_hashes is None:
        handshake_hash = secureHash(b'', algorithm)
    else:
        handshake_hash = handshake_hashes.digest(algorithm)
    
    hash_length = hashlib.new(algorithm).digest_size
    return HKDF_expand_label(secret, label, handshake_hash, hash_length, algorithm)


def bytesToNumber(b, endian='big'):
    """
    Convert a number stored in bytearray to an integer.

    By default assumes big-endian encoding of the number.
    """
    return int.from_bytes(b, byteorder=endian)


def numberToByteArray(n, howManyBytes=None, endian='big'):
    """
    Convert an integer into a bytearray, zero-pad to howManyBytes.

    The returned bytearray may be smaller than howManyBytes, but will
    not be larger.  The returned bytearray will contain a big- or little-endian
    encoding of the input integer (n). Big endian encoding is used by default.
    """
    if howManyBytes is None:
        howManyBytes = (n.bit_length() + 7) // 8
    return bytearray(n.to_bytes(howManyBytes, byteorder=endian))


def mpiToNumber(mpi):
    """Convert a MPI (OpenSSL bignum string) to an integer."""
    byte_length = (mpi[0] * 256 + mpi[1]) // 8
    return bytesToNumber(mpi[4:4+byte_length])


numBits = bit_length
numBytes = byte_length
if GMPY2_LOADED:

    def invMod(a, b):
        """Return inverse of a mod b, zero if none."""
        try:
            return int(powmod(mpz(a), -1, mpz(b)))
        except ZeroDivisionError:
            return 0
else:

    def invMod(a, b):
        """Return inverse of a mod b, zero if none."""
        try:
            return pow(a, -1, b)
        except ValueError:
            return 0
if gmpyLoaded or GMPY2_LOADED:
else:
    powMod = pow


def divceil(divident, divisor):
    """Integer division with rounding up"""
    return (divident + divisor - 1) // divisor


def getRandomPrime(bits, display=False):
    """
    Generate a random prime number of a given size.

    the number will be 'bits' bits long (i.e. generated number will be
    larger than `(2^(bits-1) * 3 ) / 2` but smaller than 2^bits.
    """
    def is_prime(n, k=5):
        if n <= 1 or n == 4:
            return False
        if n <= 3:
            return True
        
        d = n - 1
        s = 0
        while d % 2 == 0:
            d //= 2
            s += 1
        
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(s - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    while True:
        p = random.getrandbits(bits)
        p |= (1 << (bits - 1)) | 1
        if is_prime(p):
            return p


def getRandomSafePrime(bits, display=False):
    """Generate a random safe prime.

    Will generate a prime `bits` bits long (see getRandomPrime) such that
    the (p-1)/2 will also be prime.
    """
    while True:
        p = getRandomPrime(bits, display)
        if is_prime((p - 1) // 2):
            return p
