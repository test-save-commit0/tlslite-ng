from .python_rsakey import Python_RSAKey
from .python_ecdsakey import Python_ECDSAKey
from .python_dsakey import Python_DSAKey
from .python_eddsakey import Python_EdDSAKey
from .pem import dePem, pemSniff
from .asn1parser import ASN1Parser
from .cryptomath import bytesToNumber
from .compat import compatHMAC
from ecdsa.curves import NIST256p, NIST384p, NIST521p
from ecdsa.keys import SigningKey, VerifyingKey


class Python_Key(object):
    """
    Generic methods for parsing private keys from files.

    Handles both RSA and ECDSA keys, irrespective of file format.
    """

    @staticmethod
    def parsePEM(s, passwordCallback=None):
        """Parse a string containing a PEM-encoded <privateKey>."""
        pass

    @staticmethod
    def _parse_ssleay(data, key_type='rsa'):
        """
        Parse binary structure of the old SSLeay file format used by OpenSSL.

        For RSA keys.
        """
        pass

    @staticmethod
    def _parse_dsa_ssleay(data):
        """
        Parse binary structure of the old SSLeay file format used by OpenSSL.

        For DSA keys.
        """
        pass

    @staticmethod
    def _parse_ecc_ssleay(data):
        """
        Parse binary structure of the old SSLeay file format used by OpenSSL.

        For ECDSA keys.
        """
        pass

    @staticmethod
    def _parse_eddsa_private_key(data):
        """Parse a DER encoded EdDSA key."""
        pass
