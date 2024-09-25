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
        if pemSniff(s, "PRIVATE KEY"):
            der = dePem(s, "PRIVATE KEY")
            return Python_Key._parsePrivateKey(der, passwordCallback)
        elif pemSniff(s, "RSA PRIVATE KEY"):
            der = dePem(s, "RSA PRIVATE KEY")
            return Python_RSAKey._parsePKCS1(der)
        elif pemSniff(s, "EC PRIVATE KEY"):
            der = dePem(s, "EC PRIVATE KEY")
            return Python_ECDSAKey._parseECPrivateKey(der)
        elif pemSniff(s, "DSA PRIVATE KEY"):
            der = dePem(s, "DSA PRIVATE KEY")
            return Python_DSAKey._parseDSAPrivateKey(der)
        else:
            raise ValueError("Not a recognized PEM private key format")

    @staticmethod
    def _parse_ssleay(data, key_type='rsa'):
        """
        Parse binary structure of the old SSLeay file format used by OpenSSL.

        For RSA keys.
        """
        parser = ASN1Parser(data)
        version = parser.getChild(0).value[0]
        if version != 0:
            raise ValueError("Unrecognized SSLeay version")
        
        if key_type == 'rsa':
            n = bytesToNumber(parser.getChild(1).value)
            e = bytesToNumber(parser.getChild(2).value)
            d = bytesToNumber(parser.getChild(3).value)
            p = bytesToNumber(parser.getChild(4).value)
            q = bytesToNumber(parser.getChild(5).value)
            dP = bytesToNumber(parser.getChild(6).value)
            dQ = bytesToNumber(parser.getChild(7).value)
            qInv = bytesToNumber(parser.getChild(8).value)
            return Python_RSAKey(n, e, d, p, q, dP, dQ, qInv)
        else:
            raise ValueError("Unsupported key type")

    @staticmethod
    def _parse_dsa_ssleay(data):
        """
        Parse binary structure of the old SSLeay file format used by OpenSSL.

        For DSA keys.
        """
        parser = ASN1Parser(data)
        version = parser.getChild(0).value[0]
        if version != 0:
            raise ValueError("Unrecognized SSLeay version")
        
        p = bytesToNumber(parser.getChild(1).value)
        q = bytesToNumber(parser.getChild(2).value)
        g = bytesToNumber(parser.getChild(3).value)
        y = bytesToNumber(parser.getChild(4).value)
        x = bytesToNumber(parser.getChild(5).value)
        return Python_DSAKey(p, q, g, y, x)

    @staticmethod
    def _parse_ecc_ssleay(data):
        """
        Parse binary structure of the old SSLeay file format used by OpenSSL.

        For ECDSA keys.
        """
        parser = ASN1Parser(data)
        version = parser.getChild(0).value[0]
        if version != 1:
            raise ValueError("Unrecognized EC SSLeay version")
        
        private_key = parser.getChild(1).value
        oid_parser = parser.getChild(2).getChild(0)
        oid = oid_parser.value
        
        curve = None
        if oid == NIST256p.encoded_oid:
            curve = NIST256p
        elif oid == NIST384p.encoded_oid:
            curve = NIST384p
        elif oid == NIST521p.encoded_oid:
            curve = NIST521p
        else:
            raise ValueError("Unsupported curve")
        
        sk = SigningKey.from_string(private_key, curve=curve)
        vk = sk.get_verifying_key()
        return Python_ECDSAKey(sk, vk)

    @staticmethod
    def _parse_eddsa_private_key(data):
        """Parse a DER encoded EdDSA key."""
        parser = ASN1Parser(data)
        version = parser.getChild(0).value[0]
        if version != 0:
            raise ValueError("Unrecognized EdDSA version")
        
        oid_parser = parser.getChild(1)
        oid = oid_parser.value
        
        if oid == b'\x2b\x65\x70':  # Ed25519
            key_data = parser.getChild(2).getChildBytes(0)
            return Python_EdDSAKey.from_private_key(key_data)
        else:
            raise ValueError("Unsupported EdDSA algorithm")
