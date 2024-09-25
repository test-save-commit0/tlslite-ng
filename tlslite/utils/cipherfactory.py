"""Factory functions for symmetric cryptography."""
import os
from tlslite.utils import python_aes
from tlslite.utils import python_aesgcm
from tlslite.utils import python_aesccm
from tlslite.utils import python_chacha20_poly1305
from tlslite.utils import python_rc4
from tlslite.utils import python_tripledes
from tlslite.utils import openssl_aesccm
from tlslite.utils import openssl_aesgcm
from tlslite.utils import cryptomath
tripleDESPresent = True
"""Inform if the 3DES algorithm is supported."""
if cryptomath.m2cryptoLoaded:
    from tlslite.utils import openssl_aes
    from tlslite.utils import openssl_rc4
    from tlslite.utils import openssl_tripledes
if cryptomath.pycryptoLoaded:
    from tlslite.utils import pycrypto_aes
    from tlslite.utils import pycrypto_aesgcm
    from tlslite.utils import pycrypto_rc4
    from tlslite.utils import pycrypto_tripledes


def createAES(key, IV, implList=None):
    """Create a new AES object.

    :type key: str
    :param key: A 16, 24, or 32 byte string.

    :type IV: str
    :param IV: A 16 byte string

    :rtype: tlslite.utils.AES
    :returns: An AES object.
    """
    if implList is None:
        implList = [openssl_aes, pycrypto_aes, python_aes]

    for impl in implList:
        try:
            return impl.new(key, impl.MODE_CBC, IV)
        except (ImportError, AttributeError):
            pass

    raise NotImplementedError("No AES implementation available")


def createAESCTR(key, IV, implList=None):
    """Create a new AESCTR object.

    :type key: str
    :param key: A 16, 24, or 32 byte string.

    :type IV: str
    :param IV: A 8 or 12 byte string

    :rtype: tlslite.utils.AES
    :returns: An AES object.
    """
    if implList is None:
        implList = [openssl_aes, pycrypto_aes, python_aes]

    for impl in implList:
        try:
            return impl.new(key, impl.MODE_CTR, IV)
        except (ImportError, AttributeError):
            pass

    raise NotImplementedError("No AESCTR implementation available")


def createAESGCM(key, implList=None):
    """Create a new AESGCM object.

    :type key: bytearray
    :param key: A 16 or 32 byte byte array.

    :rtype: tlslite.utils.AESGCM
    :returns: An AESGCM object.
    """
    if implList is None:
        implList = [openssl_aesgcm, pycrypto_aesgcm, python_aesgcm]

    for impl in implList:
        try:
            return impl.new(key)
        except (ImportError, AttributeError):
            pass

    raise NotImplementedError("No AESGCM implementation available")


def createAESCCM(key, implList=None):
    """ Create a new AESCCM object.

    :type key: bytearray
    :param key: A 16 or 32 byte byte array to serve as key.

    :rtype: tlslite.utils.AESCCM
    :returns: An AESCCM object.
    """
    if implList is None:
        implList = [openssl_aesccm, python_aesccm]

    for impl in implList:
        try:
            return impl.new(key)
        except (ImportError, AttributeError):
            pass

    raise NotImplementedError("No AESCCM implementation available")


def createAESCCM_8(key, implList=None):
    """ Create a new AESCCM object with truncated tag.

    :type key: bytearray
    :param key: A 16 or 32 byte byte array to serve as key.

    :rtype: tlslite.utils.AESCCM
    :returns: An AESCCM object.
    """
    if implList is None:
        implList = [openssl_aesccm, python_aesccm]

    for impl in implList:
        try:
            return impl.new(key, tag_length=8)
        except (ImportError, AttributeError):
            pass

    raise NotImplementedError("No AESCCM_8 implementation available")


def createCHACHA20(key, implList=None):
    """Create a new CHACHA20_POLY1305 object.

    :type key: bytearray
    :param key: a 32 byte array to serve as key

    :rtype: tlslite.utils.CHACHA20_POLY1305
    :returns: A ChaCha20/Poly1305 object
    """
    if implList is None:
        implList = [python_chacha20_poly1305]

    for impl in implList:
        try:
            return impl.new(key)
        except (ImportError, AttributeError):
            pass

    raise NotImplementedError("No ChaCha20/Poly1305 implementation available")


def createRC4(key, IV, implList=None):
    """Create a new RC4 object.

    :type key: str
    :param key: A 16 to 32 byte string.

    :type IV: object
    :param IV: Ignored, whatever it is.

    :rtype: tlslite.utils.RC4
    :returns: An RC4 object.
    """
    if implList is None:
        implList = [openssl_rc4, pycrypto_rc4, python_rc4]

    for impl in implList:
        try:
            return impl.new(key)
        except (ImportError, AttributeError):
            pass

    raise NotImplementedError("No RC4 implementation available")


def createTripleDES(key, IV, implList=None):
    """Create a new 3DES object.

    :type key: str
    :param key: A 24 byte string.

    :type IV: str
    :param IV: An 8 byte string

    :rtype: tlslite.utils.TripleDES
    :returns: A 3DES object.
    """
    if implList is None:
        implList = [openssl_tripledes, pycrypto_tripledes, python_tripledes]

    for impl in implList:
        try:
            return impl.new(key, impl.MODE_CBC, IV)
        except (ImportError, AttributeError):
            pass

    raise NotImplementedError("No 3DES implementation available")
