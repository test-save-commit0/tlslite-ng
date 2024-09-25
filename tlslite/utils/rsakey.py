"""Abstract class for RSA."""
from .cryptomath import *
from . import tlshashlib as hashlib
from ..errors import MaskTooLongError, MessageTooLongError, EncodingError, InvalidSignature, UnknownRSAType
from .constanttime import ct_isnonzero_u32, ct_neq_u32, ct_lsb_prop_u8, ct_lsb_prop_u16, ct_lt_u32


class RSAKey(object):
    """This is an abstract base class for RSA keys.

    Particular implementations of RSA keys, such as
    :py:class:`~.openssl_rsakey.OpenSSL_RSAKey`,
    :py:class:`~.python_rsakey.Python_RSAKey`, and
    :py:class:`~.pycrypto_rsakey.PyCrypto_RSAKey`,
    inherit from this.

    To create or parse an RSA key, don't use one of these classes
    directly.  Instead, use the factory functions in
    :py:class:`~tlslite.utils.keyfactory`.
    """

    def __init__(self, n=0, e=0, key_type='rsa'):
        """Create a new RSA key.

        If n and e are passed in, the new key will be initialized.

        :type n: int
        :param n: RSA modulus.

        :type e: int
        :param e: RSA public exponent.

        :type key_type: str
        :param key_type: type of the RSA key, "rsa" for rsaEncryption
            (universal, able to perform all operations) or "rsa-pss" for a
            RSASSA-PSS key (able to perform only RSA-PSS signature verification
            and creation)
        """
        self.n = n
        self.e = e
        self.key_type = key_type
        self._key_hash = None
        if self.key_type not in ['rsa', 'rsa-pss']:
            raise ValueError("Invalid key_type. Must be 'rsa' or 'rsa-pss'.")

    def __len__(self):
        """Return the length of this key in bits.

        :rtype: int
        """
        return numBits(self.n)

    def hasPrivateKey(self):
        """Return whether or not this key has a private component.

        :rtype: bool
        """
        return hasattr(self, 'd')

    def hashAndSign(self, bytes, rsaScheme='PKCS1', hAlg='sha1', sLen=0):
        """Hash and sign the passed-in bytes.

        This requires the key to have a private component.  It performs
        a PKCS1 or PSS signature on the passed-in data with selected hash
        algorithm.

        :type bytes: bytes-like object
        :param bytes: The value which will be hashed and signed.

        :type rsaScheme: str
        :param rsaScheme: The type of RSA scheme that will be applied,
                          "PKCS1" for RSASSA-PKCS#1 v1.5 signature and "PSS"
                          for RSASSA-PSS with MGF1 signature method

        :type hAlg: str
        :param hAlg: The hash algorithm that will be used

        :type sLen: int
        :param sLen: The length of intended salt value, applicable only
                     for RSASSA-PSS signatures

        :rtype: bytearray
        :returns: A PKCS1 or PSS signature on the passed-in data.
        """
        pass

    def hashAndVerify(self, sigBytes, bytes, rsaScheme='PKCS1', hAlg='sha1',
        sLen=0):
        """Hash and verify the passed-in bytes with the signature.

        This verifies a PKCS1 or PSS signature on the passed-in data
        with selected hash algorithm.

        :type sigBytes: bytes-like object
        :param sigBytes: A PKCS1 or PSS signature.

        :type bytes: bytes-like object
        :param bytes: The value which will be hashed and verified.

        :type rsaScheme: str
        :param rsaScheme: The type of RSA scheme that will be applied,
                          "PKCS1" for RSASSA-PKCS#1 v1.5 signature and "PSS"
                          for RSASSA-PSS with MGF1 signature method

        :type hAlg: str
        :param hAlg: The hash algorithm that will be used

        :type sLen: int
        :param sLen: The length of intended salt value, applicable only
                     for RSASSA-PSS signatures

        :rtype: bool
        :returns: Whether the signature matches the passed-in data.
        """
        pass

    def MGF1(self, mgfSeed, maskLen, hAlg):
        """Generate mask from passed-in seed.

        This generates mask based on passed-in seed and output maskLen.

        :type mgfSeed: bytearray
        :param mgfSeed: Seed from which mask will be generated.

        :type maskLen: int
        :param maskLen: Wished length of the mask, in octets

        :rtype: bytearray
        :returns: Mask
        """
        hashObj = hashlib.new(hAlg)
        hLen = hashObj.digest_size
        if maskLen > (2**32) * hLen:
            raise ValueError("mask too long")
        T = bytearray()
        for counter in range(ceil(maskLen / hLen)):
            C = i2osp(counter, 4)
            hashObj = hashlib.new(hAlg)
            hashObj.update(mgfSeed + C)
            T += hashObj.digest()
        return T[:maskLen]

    def EMSA_PSS_encode(self, mHash, emBits, hAlg, sLen=0):
        """Encode the passed in message

        This encodes the message using selected hash algorithm

        :type mHash: bytearray
        :param mHash: Hash of message to be encoded

        :type emBits: int
        :param emBits: maximal length of returned EM

        :type hAlg: str
        :param hAlg: hash algorithm to be used

        :type sLen: int
        :param sLen: length of salt"""
        hashObj = hashlib.new(hAlg)
        hLen = hashObj.digest_size
        emLen = ceil(emBits / 8)
        
        if emLen < hLen + sLen + 2:
            raise ValueError("encoding error")
        
        salt = getRandomBytes(sLen)
        M_prime = b'\x00' * 8 + mHash + salt
        
        H = hashlib.new(hAlg, M_prime).digest()
        PS = b'\x00' * (emLen - sLen - hLen - 2)
        DB = PS + b'\x01' + salt
        dbMask = self.MGF1(H, emLen - hLen - 1, hAlg)
        maskedDB = bytearray(a ^ b for a, b in zip(DB, dbMask))
        
        maskedDB[0] &= 0xFF >> (8 * emLen - emBits)
        EM = maskedDB + H + b'\xbc'
        return EM

    def RSASSA_PSS_sign(self, mHash, hAlg, sLen=0):
        """"Sign the passed in message

        This signs the message using selected hash algorithm

        :type mHash: bytes-like object
        :param mHash: Hash of message to be signed

        :type hAlg: str
        :param hAlg: hash algorithm to be used

        :type sLen: int
        :param sLen: length of salt"""
        if not self.hasPrivateKey():
            raise ValueError("Private key not available")
        
        EM = self.EMSA_PSS_encode(mHash, len(self) - 1, hAlg, sLen)
        m = bytes_to_int(EM)
        s = self._raw_private_key_op(m)
        S = int_to_bytes(s, len(self) // 8)
        return S

    def EMSA_PSS_verify(self, mHash, EM, emBits, hAlg, sLen=0):
        """Verify signature in passed in encoded message

        This verifies the signature in encoded message

        :type mHash: bytes-like object
        :param mHash: Hash of the original not signed message

        :type EM: bytes-like object
        :param EM: Encoded message

        :type emBits: int
        :param emBits: Length of the encoded message in bits

        :type hAlg: str
        :param hAlg: hash algorithm to be used

        :type sLen: int
        :param sLen: Length of salt
        """
        hashObj = hashlib.new(hAlg)
        hLen = hashObj.digest_size
        emLen = ceil(emBits / 8)
        
        if emLen < hLen + sLen + 2:
            return False
        if EM[-1] != 0xbc:
            return False
        
        maskedDB = EM[:emLen - hLen - 1]
        H = EM[emLen - hLen - 1:-1]
        
        if maskedDB[0] & (0xFF << (8 - (emBits & 7))):
            return False
        
        dbMask = self.MGF1(H, emLen - hLen - 1, hAlg)
        DB = bytearray(a ^ b for a, b in zip(maskedDB, dbMask))
        DB[0] &= 0xFF >> (8 * emLen - emBits)
        
        if any(DB[i] != 0 for i in range(emLen - hLen - sLen - 2)):
            return False
        if DB[emLen - hLen - sLen - 2] != 0x01:
            return False
        
        salt = DB[-sLen:] if sLen > 0 else b''
        M_prime = b'\x00' * 8 + mHash + salt
        H_prime = hashlib.new(hAlg, M_prime).digest()
        
        return ct_eq_u32(H, H_prime)

    def RSASSA_PSS_verify(self, mHash, S, hAlg, sLen=0):
        """Verify the signature in passed in message

        This verifies the signature in the signed message

        :type mHash: bytes-like object
        :param mHash: Hash of original message

        :type S: bytes-like object
        :param S: Signed message

        :type hAlg: str
        :param hAlg: Hash algorithm to be used

        :type sLen: int
        :param sLen: Length of salt
        """
        if len(S) != len(self) // 8:
            return False
        
        s = bytes_to_int(S)
        m = self._raw_public_key_op(s)
        EM = int_to_bytes(m, len(self) // 8)
        
        return self.EMSA_PSS_verify(mHash, EM, len(self) - 1, hAlg, sLen)

    def _raw_pkcs1_sign(self, bytes):
        """Perform signature on raw data, add PKCS#1 padding."""
        if not self.hasPrivateKey():
            raise ValueError("Private key not available")
        
        paddedBytes = self._addPKCS1Padding(bytes, 1)
        m = bytes_to_int(paddedBytes)
        s = self._raw_private_key_op(m)
        return int_to_bytes(s, len(self) // 8)

    def sign(self, bytes, padding='pkcs1', hashAlg=None, saltLen=None):
        """Sign the passed-in bytes.

        This requires the key to have a private component.  It performs
        a PKCS1 signature on the passed-in data.

        :type bytes: bytes-like object
        :param bytes: The value which will be signed.

        :type padding: str
        :param padding: name of the rsa padding mode to use, supported:
            "pkcs1" for RSASSA-PKCS1_1_5 and "pss" for RSASSA-PSS.

        :type hashAlg: str
        :param hashAlg: name of hash to be encoded using the PKCS#1 prefix
            for "pkcs1" padding or the hash used for MGF1 in "pss". Parameter
            is mandatory for "pss" padding.

        :type saltLen: int
        :param saltLen: length of salt used for the PSS padding. Default
            is the length of the hash output used.

        :rtype: bytearray
        :returns: A PKCS1 signature on the passed-in data.
        """
        if not self.hasPrivateKey():
            raise ValueError("Private key not available")

        if padding == 'pkcs1':
            hashBytes = hashlib.new(hashAlg, bytes).digest() if hashAlg else bytes
            prefixedHashBytes = self.addPKCS1Prefix(hashBytes, hashAlg) if hashAlg else hashBytes
            return self._raw_pkcs1_sign(prefixedHashBytes)
        elif padding == 'pss':
            if not hashAlg:
                raise ValueError("hashAlg is mandatory for PSS padding")
            hashBytes = hashlib.new(hashAlg, bytes).digest()
            saltLen = saltLen or len(hashBytes)
            return self.RSASSA_PSS_sign(hashBytes, hashAlg, saltLen)
        else:
            raise ValueError("Unsupported padding mode")

    def _raw_pkcs1_verify(self, sigBytes, bytes):
        """Perform verification operation on raw PKCS#1 padded signature"""
        s = bytes_to_int(sigBytes)
        m = self._raw_public_key_op(s)
        em = int_to_bytes(m, len(self) // 8)
        return self._removePKCS1Padding(em) == bytes

    def verify(self, sigBytes, bytes, padding='pkcs1', hashAlg=None,
        saltLen=None):
        """Verify the passed-in bytes with the signature.

        This verifies a PKCS1 signature on the passed-in data.

        :type sigBytes: bytes-like object
        :param sigBytes: A PKCS1 signature.

        :type bytes: bytes-like object
        :param bytes: The value which will be verified.

        :rtype: bool
        :returns: Whether the signature matches the passed-in data.
        """
        if padding == 'pkcs1':
            hashBytes = hashlib.new(hashAlg, bytes).digest() if hashAlg else bytes
            prefixedHashBytes = self.addPKCS1Prefix(hashBytes, hashAlg) if hashAlg else hashBytes
            return self._raw_pkcs1_verify(sigBytes, prefixedHashBytes)
        elif padding == 'pss':
            if not hashAlg:
                raise ValueError("hashAlg is mandatory for PSS padding")
            hashBytes = hashlib.new(hashAlg, bytes).digest()
            saltLen = saltLen or len(hashBytes)
            return self.RSASSA_PSS_verify(hashBytes, sigBytes, hashAlg, saltLen)
        else:
            raise ValueError("Unsupported padding mode")

    def encrypt(self, bytes):
        """Encrypt the passed-in bytes.

        This performs PKCS1 encryption of the passed-in data.

        :type bytes: bytes-like object
        :param bytes: The value which will be encrypted.

        :rtype: bytearray
        :returns: A PKCS1 encryption of the passed-in data.
        """
        pass

    def _dec_prf(self, key, label, out_len):
        """PRF for deterministic implicit rejection in the RSA decryption.

        :param bytes key: key to use for derivation
        :param bytes label: name of the keystream generated
        :param int out_len: length of output, in bits
        :rtype: bytes
        :returns: a random bytestring
        """
        pass

    def decrypt(self, encBytes):
        """Decrypt the passed-in bytes.

        This requires the key to have a private component.  It performs
        PKCS#1 v1.5 decryption operation of the passed-in data.

        Note: as a workaround against Bleichenbacher-like attacks, it will
        return a deterministically selected random message in case the padding
        checks failed. It returns an error (None) only in case the ciphertext
        is of incorrect length or encodes an integer bigger than the modulus
        of the key (i.e. it's publically invalid).

        :type encBytes: bytes-like object
        :param encBytes: The value which will be decrypted.

        :rtype: bytearray or None
        :returns: A PKCS#1 v1.5 decryption of the passed-in data or None if
            the provided data is not properly formatted. Note: encrypting
            an empty string is correct, so it may return an empty bytearray
            for some ciphertexts.
        """
        pass

    def acceptsPassword(self):
        """Return True if the write() method accepts a password for use
        in encrypting the private key.

        :rtype: bool
        """
        pass

    def write(self, password=None):
        """Return a string containing the key.

        :rtype: str
        :returns: A string describing the key, in whichever format (PEM)
            is native to the implementation.
        """
        pass

    @staticmethod
    def generate(bits, key_type='rsa'):
        """Generate a new key with the specified bit length.

        :rtype: ~tlslite.utils.RSAKey.RSAKey
        """
        pass

    @classmethod
    def addPKCS1SHA1Prefix(cls, hashBytes, withNULL=True):
        """Add PKCS#1 v1.5 algorithm identifier prefix to SHA1 hash bytes"""
        pass
    _pkcs1Prefixes = {'md5': bytearray([48, 32, 48, 12, 6, 8, 42, 134, 72, 
        134, 247, 13, 2, 5, 5, 0, 4, 16]), 'sha1': bytearray([48, 33, 48, 9,
        6, 5, 43, 14, 3, 2, 26, 5, 0, 4, 20]), 'sha224': bytearray([48, 45,
        48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 4, 5, 0, 4, 28]),
        'sha256': bytearray([48, 49, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 
        4, 2, 1, 5, 0, 4, 32]), 'sha384': bytearray([48, 65, 48, 13, 6, 9, 
        96, 134, 72, 1, 101, 3, 4, 2, 2, 5, 0, 4, 48]), 'sha512': bytearray
        ([48, 81, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 3, 5, 0, 4, 64])}

    @classmethod
    def addPKCS1Prefix(cls, data, hashName):
        """Add the PKCS#1 v1.5 algorithm identifier prefix to hash bytes"""
        pass
