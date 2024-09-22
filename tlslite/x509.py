"""Class representing an X.509 certificate."""
from ecdsa.keys import VerifyingKey
from .utils.asn1parser import ASN1Parser
from .utils.cryptomath import *
from .utils.keyfactory import _createPublicRSAKey, _create_public_ecdsa_key, _create_public_dsa_key, _create_public_eddsa_key
from .utils.pem import *
from .utils.compat import compatHMAC, b2a_hex
from .constants import AlgorithmOID, RSA_PSS_OID


class X509(object):
    """
    This class represents an X.509 certificate.

    :vartype bytes: bytearray
    :ivar bytes: The DER-encoded ASN.1 certificate

    :vartype publicKey: ~tlslite.utils.rsakey.RSAKey
    :ivar publicKey: The subject public key from the certificate.

    :vartype subject: bytearray
    :ivar subject: The DER-encoded ASN.1 subject distinguished name.

    :vartype certAlg: str
    :ivar certAlg: algorithm of the public key, "rsa" for RSASSA-PKCS#1 v1.5,
        "rsa-pss" for RSASSA-PSS, "ecdsa" for ECDSA
    """

    def __init__(self):
        """Create empty certificate object."""
        self.bytes = bytearray(0)
        self.serial_number = None
        self.subject_public_key = None
        self.publicKey = None
        self.subject = None
        self.certAlg = None
        self.sigalg = None
        self.issuer = None

    def __hash__(self):
        """Calculate hash of object."""
        return hash(bytes(self.bytes))

    def __eq__(self, other):
        """Compare other object for equality."""
        if not hasattr(other, 'bytes'):
            return NotImplemented
        return self.bytes == other.bytes

    def __ne__(self, other):
        """Compare with other object for inequality."""
        if not hasattr(other, 'bytes'):
            return NotImplemented
        return not self == other

    def parse(self, s):
        """
        Parse a PEM-encoded X.509 certificate.

        :type s: str
        :param s: A PEM-encoded X.509 certificate (i.e. a base64-encoded
            certificate wrapped with "-----BEGIN CERTIFICATE-----" and
            "-----END CERTIFICATE-----" tags).
        """
        pass

    def parseBinary(self, cert_bytes):
        """
        Parse a DER-encoded X.509 certificate.

        :type bytes: L{str} (in python2) or L{bytearray} of unsigned bytes
        :param bytes: A DER-encoded X.509 certificate.
        """
        pass

    def _eddsa_pubkey_parsing(self, subject_public_key_info):
        """
        Convert the raw DER encoded EdDSA parameters into public key object.

        :param subject_public_key_info: bytes like object with the DER encoded
            public key in it
        """
        pass

    def _rsa_pubkey_parsing(self, subject_public_key_info):
        """
        Parse the RSA public key from the certificate.

        :param subject_public_key_info: ASN1Parser object with subject
            public key info of X.509 certificate
        """
        pass

    def _ecdsa_pubkey_parsing(self, subject_public_key_info):
        """
        Convert the raw DER encoded ECDSA parameters into public key object

        :param subject_public_key_info: bytes like object with DER encoded
            public key in it
        """
        pass

    def _dsa_pubkey_parsing(self, subject_public_key_info):
        """
        Convert the raw DER encoded DSA parameters into public key object

        :param subject_public_key_info: bytes like object with DER encoded
          global parameters and public key in it
        """
        pass

    def getFingerprint(self):
        """
        Get the hex-encoded fingerprint of this certificate.

        :rtype: str
        :returns: A hex-encoded fingerprint.
        """
        pass

    def writeBytes(self):
        """Serialise object to a DER encoded string."""
        pass
