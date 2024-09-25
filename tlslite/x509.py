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
        bytes = dePem(s, "CERTIFICATE")
        return self.parseBinary(bytes)

    def parseBinary(self, cert_bytes):
        """
        Parse a DER-encoded X.509 certificate.

        :type bytes: L{str} (in python2) or L{bytearray} of unsigned bytes
        :param bytes: A DER-encoded X.509 certificate.
        """
        self.bytes = bytearray(cert_bytes)
        parser = ASN1Parser(self.bytes)

        cert = parser.getChild(0)
        tbsCertificate = cert.getChild(0)

        self.serial_number = tbsCertificate.getChild(1).value

        self.issuer = tbsCertificate.getChild(3).value
        self.subject = tbsCertificate.getChild(5).value

        subject_public_key_info = tbsCertificate.getChild(6)
        algorithm = subject_public_key_info.getChild(0)
        alg_oid = algorithm.getChild(0).value

        if alg_oid == AlgorithmOID.RSA:
            self.certAlg = "rsa"
            self._rsa_pubkey_parsing(subject_public_key_info)
        elif alg_oid == RSA_PSS_OID:
            self.certAlg = "rsa-pss"
            self._rsa_pubkey_parsing(subject_public_key_info)
        elif alg_oid == AlgorithmOID.ECDSA:
            self.certAlg = "ecdsa"
            self._ecdsa_pubkey_parsing(subject_public_key_info)
        elif alg_oid == AlgorithmOID.DSA:
            self.certAlg = "dsa"
            self._dsa_pubkey_parsing(subject_public_key_info)
        elif alg_oid in (AlgorithmOID.Ed25519, AlgorithmOID.Ed448):
            self.certAlg = "eddsa"
            self._eddsa_pubkey_parsing(subject_public_key_info)
        else:
            raise SyntaxError("Unsupported public key algorithm")

        self.sigalg = cert.getChild(1).getChild(0).value

    def _eddsa_pubkey_parsing(self, subject_public_key_info):
        """
        Convert the raw DER encoded EdDSA parameters into public key object.

        :param subject_public_key_info: bytes like object with the DER encoded
            public key in it
        """
        public_key = subject_public_key_info.getChild(1).value
        self.publicKey = _create_public_eddsa_key(public_key)

    def _rsa_pubkey_parsing(self, subject_public_key_info):
        """
        Parse the RSA public key from the certificate.

        :param subject_public_key_info: ASN1Parser object with subject
            public key info of X.509 certificate
        """
        public_key = subject_public_key_info.getChild(1).value
        key_parser = ASN1Parser(public_key)
        modulus = key_parser.getChild(0).value
        public_exponent = key_parser.getChild(1).value
        self.publicKey = _createPublicRSAKey(modulus, public_exponent)

    def _ecdsa_pubkey_parsing(self, subject_public_key_info):
        """
        Convert the raw DER encoded ECDSA parameters into public key object

        :param subject_public_key_info: bytes like object with DER encoded
            public key in it
        """
        public_key = subject_public_key_info.getChild(1).value
        self.publicKey = _create_public_ecdsa_key(public_key)

    def _dsa_pubkey_parsing(self, subject_public_key_info):
        """
        Convert the raw DER encoded DSA parameters into public key object

        :param subject_public_key_info: bytes like object with DER encoded
          global parameters and public key in it
        """
        algorithm_params = subject_public_key_info.getChild(0).getChild(1)
        p = algorithm_params.getChild(0).value
        q = algorithm_params.getChild(1).value
        g = algorithm_params.getChild(2).value
        y = subject_public_key_info.getChild(1).value
        self.publicKey = _create_public_dsa_key(p, q, g, y)

    def getFingerprint(self):
        """
        Get the hex-encoded fingerprint of this certificate.

        :rtype: str
        :returns: A hex-encoded fingerprint.
        """
        return b2a_hex(compatHMAC(self.bytes, "sha1")).decode("ascii")

    def writeBytes(self):
        """Serialise object to a DER encoded string."""
        return bytes(self.bytes)
