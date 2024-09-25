"""Factory functions for asymmetric cryptography."""
from .compat import *
from .rsakey import RSAKey
from .python_rsakey import Python_RSAKey
from .python_ecdsakey import Python_ECDSAKey
from .python_dsakey import Python_DSAKey
from .python_eddsakey import Python_EdDSAKey
from tlslite.utils import cryptomath
if cryptomath.m2cryptoLoaded:
    from .openssl_rsakey import OpenSSL_RSAKey
if cryptomath.pycryptoLoaded:
    from .pycrypto_rsakey import PyCrypto_RSAKey


def generateRSAKey(bits, implementations=['openssl', 'python']):
    """Generate an RSA key with the specified bit length.

    :type bits: int
    :param bits: Desired bit length of the new key's modulus.

    :rtype: ~tlslite.utils.rsakey.RSAKey
    :returns: A new RSA private key.
    """
    for implementation in implementations:
        if implementation == 'openssl' and cryptomath.m2cryptoLoaded:
            return OpenSSL_RSAKey.generate(bits)
        elif implementation == 'python':
            return Python_RSAKey.generate(bits)
    raise ValueError("No supported implementation available")


def parsePEMKey(s, private=False, public=False, passwordCallback=None,
    implementations=['openssl', 'python']):
    """Parse a PEM-format key.

    The PEM format is used by OpenSSL and other tools.  The
    format is typically used to store both the public and private
    components of a key.  For example::

       -----BEGIN RSA PRIVATE KEY-----
        MIICXQIBAAKBgQDYscuoMzsGmW0pAYsmyHltxB2TdwHS0dImfjCMfaSDkfLdZY5+
        dOWORVns9etWnr194mSGA1F0Pls/VJW8+cX9+3vtJV8zSdANPYUoQf0TP7VlJxkH
        dSRkUbEoz5bAAs/+970uos7n7iXQIni+3erUTdYEk2iWnMBjTljfgbK/dQIDAQAB
        AoGAJHoJZk75aKr7DSQNYIHuruOMdv5ZeDuJvKERWxTrVJqE32/xBKh42/IgqRrc
        esBN9ZregRCd7YtxoL+EVUNWaJNVx2mNmezEznrc9zhcYUrgeaVdFO2yBF1889zO
        gCOVwrO8uDgeyj6IKa25H6c1N13ih/o7ZzEgWbGG+ylU1yECQQDv4ZSJ4EjSh/Fl
        aHdz3wbBa/HKGTjC8iRy476Cyg2Fm8MZUe9Yy3udOrb5ZnS2MTpIXt5AF3h2TfYV
        VoFXIorjAkEA50FcJmzT8sNMrPaV8vn+9W2Lu4U7C+K/O2g1iXMaZms5PC5zV5aV
        CKXZWUX1fq2RaOzlbQrpgiolhXpeh8FjxwJBAOFHzSQfSsTNfttp3KUpU0LbiVvv
        i+spVSnA0O4rq79KpVNmK44Mq67hsW1P11QzrzTAQ6GVaUBRv0YS061td1kCQHnP
        wtN2tboFR6lABkJDjxoGRvlSt4SOPr7zKGgrWjeiuTZLHXSAnCY+/hr5L9Q3ZwXG
        6x6iBdgLjVIe4BZQNtcCQQDXGv/gWinCNTN3MPWfTW/RGzuMYVmyBFais0/VrgdH
        h1dLpztmpQqfyH/zrBXQ9qL/zR4ojS6XYneO/U18WpEe
        -----END RSA PRIVATE KEY-----

    To generate a key like this with OpenSSL, run::

        openssl genrsa 2048 > key.pem

    This format also supports password-encrypted private keys.  TLS
    Lite can only handle password-encrypted private keys when OpenSSL
    and M2Crypto are installed.  In this case, passwordCallback will be
    invoked to query the user for the password.

    :type s: str
    :param s: A string containing a PEM-encoded public or private key.

    :type private: bool
    :param private: If True, a :py:class:`SyntaxError` will be raised if the
        private key component is not present.

    :type public: bool
    :param public: If True, the private key component (if present) will
        be discarded, so this function will always return a public key.

    :type passwordCallback: callable
    :param passwordCallback: This function will be called, with no
        arguments, if the PEM-encoded private key is password-encrypted.
        The callback should return the password string.  If the password is
        incorrect, SyntaxError will be raised.  If no callback is passed
        and the key is password-encrypted, a prompt will be displayed at
        the console.

    :rtype: ~tlslite.utils.rsakey.RSAKey
    :returns: An RSA key.

    :raises SyntaxError: If the key is not properly formatted.
    """
    for implementation in implementations:
        if implementation == 'openssl' and cryptomath.m2cryptoLoaded:
            try:
                return OpenSSL_RSAKey.parse(s, private, public, passwordCallback)
            except:
                pass
        elif implementation == 'python':
            try:
                return Python_RSAKey.parse(s, private, public)
            except:
                pass
    raise SyntaxError("Unable to parse the PEM key")


def parseAsPublicKey(s):
    """Parse a PEM-formatted public key.

    :type s: str
    :param s: A string containing a PEM-encoded public or private key.

    :rtype: ~tlslite.utils.rsakey.RSAKey
    :returns: An RSA public key.

    :raises SyntaxError: If the key is not properly formatted.
    """
    return parsePEMKey(s, private=False, public=True)


def parsePrivateKey(s):
    """Parse a PEM-formatted private key.

    :type s: str
    :param s: A string containing a PEM-encoded private key.

    :rtype: ~tlslite.utils.rsakey.RSAKey
    :returns: An RSA private key.

    :raises SyntaxError: If the key is not properly formatted.
    """
    return parsePEMKey(s, private=True)


def _createPublicKey(key):
    """
    Create a new public key.  Discard any private component,
    and return the most efficient key possible.
    """
    if isinstance(key, RSAKey):
        return _createPublicRSAKey(key)
    elif isinstance(key, Python_ECDSAKey):
        return _create_public_ecdsa_key(key.public_key().point.x(), key.public_key().point.y(), key.curve.name)
    elif isinstance(key, Python_DSAKey):
        return _create_public_dsa_key(key.p, key.q, key.g, key.y)
    elif isinstance(key, Python_EdDSAKey):
        return _create_public_eddsa_key(key.public_key())
    else:
        raise ValueError("Unsupported key type")


def _createPrivateKey(key):
    """
    Create a new private key.  Return the most efficient key possible.
    """
    if isinstance(key, RSAKey):
        if cryptomath.m2cryptoLoaded:
            return OpenSSL_RSAKey(key.n, key.e, key.d, key.p, key.q, key.dP, key.dQ, key.qInv)
        else:
            return Python_RSAKey(key.n, key.e, key.d, key.p, key.q, key.dP, key.dQ, key.qInv)
    elif isinstance(key, Python_ECDSAKey):
        return key
    elif isinstance(key, Python_DSAKey):
        return key
    elif isinstance(key, Python_EdDSAKey):
        return key
    else:
        raise ValueError("Unsupported key type")


def _create_public_ecdsa_key(point_x, point_y, curve_name, implementations=
    ('python',)):
    """
    Convert public key parameters into concrete implementation of verifier.

    The public key in ECDSA is a point on elliptic curve, so it consists of
    two integers that identify the point and the name of the curve on which
    it needs to lie on.

    :type point_x: int
    :param point_x: the 'x' coordinate of the point
    :type point_y: int
    :param point_y: the 'y' coordinate of the point
    :type curve_name: str
    :param curve_name: well known name of the curve (e.g. 'NIST256p' or
        'SECP256k1')
    :type implementations: iterable of str
    :param implementations: list of implementations that can be used as the
        concrete implementation of the verifying key (only 'python' is
        supported currently)
    """
    if 'python' in implementations:
        from ecdsa import NIST256p, SECP256k1, VerifyingKey, Point
        if curve_name == 'NIST256p':
            curve = NIST256p
        elif curve_name == 'SECP256k1':
            curve = SECP256k1
        else:
            raise ValueError("Unsupported curve name")
        
        point = Point(curve.curve, point_x, point_y)
        vk = VerifyingKey.from_public_point(point, curve)
        return Python_ECDSAKey(vk)
    else:
        raise ValueError("No supported implementation available")


def _create_public_eddsa_key(public_key, implementations=('python',)):
    """
    Convert the python-ecdsa public key into concrete implementation of
    verifier.
    """
    if 'python' in implementations:
        return Python_EdDSAKey(public_key)
    else:
        raise ValueError("No supported implementation available")


def _create_public_dsa_key(p, q, g, y, implementations=('python',)):
    """
    Convert public key parameters into concrete implementation of verifier.

    The public key in DSA consists of four integers.

    :type p: int
    :param p: domain parameter, prime num defining Gaolis Field
    :type q: int
    :param q: domain parameter, prime factor of p-1
    :type g: int
    :param g: domain parameter, generator of q-order cyclic group GP(p)
    :type y: int
    :param y: public key
    :type implementations: iterable of str
    :param implementations: list of implementations that can be used as the
        concrete implementation of the verifying key (only 'python' is
        supported currently)
    """
    if 'python' in implementations:
        return Python_DSAKey(p, q, g, y)
    else:
        raise ValueError("No supported implementation available")
