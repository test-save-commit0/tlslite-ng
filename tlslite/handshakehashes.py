"""Handling cryptographic hashes for handshake protocol"""
from .utils.compat import compat26Str, compatHMAC
from .utils.cryptomath import MD5, SHA1
from .utils import tlshashlib as hashlib


class HandshakeHashes(object):
    """
    Store and calculate necessary hashes for handshake protocol

    Calculates message digests of messages exchanged in handshake protocol
    of SSLv3 and TLS.
    """

    def __init__(self):
        """Create instance"""
        self._handshakeMD5 = hashlib.md5()
        self._handshakeSHA = hashlib.sha1()
        self._handshakeSHA224 = hashlib.sha224()
        self._handshakeSHA256 = hashlib.sha256()
        self._handshakeSHA384 = hashlib.sha384()
        self._handshakeSHA512 = hashlib.sha512()
        self._handshake_buffer = bytearray()

    def update(self, data):
        """
        Add `data` to hash input.

        :param bytearray data: serialized TLS handshake message
        """
        self._handshakeMD5.update(compatHMAC(data))
        self._handshakeSHA.update(compatHMAC(data))
        self._handshakeSHA224.update(compatHMAC(data))
        self._handshakeSHA256.update(compatHMAC(data))
        self._handshakeSHA384.update(compatHMAC(data))
        self._handshakeSHA512.update(compatHMAC(data))
        self._handshake_buffer += data

    def digest(self, digest=None):
        """
        Calculate and return digest for the already consumed data.

        Used for Finished and CertificateVerify messages.

        :param str digest: name of digest to return
        """
        if digest is None:
            return self._handshakeMD5.digest() + self._handshakeSHA.digest()
        elif digest == 'md5':
            return self._handshakeMD5.digest()
        elif digest == 'sha1':
            return self._handshakeSHA.digest()
        elif digest == 'sha224':
            return self._handshakeSHA224.digest()
        elif digest == 'sha256':
            return self._handshakeSHA256.digest()
        elif digest == 'sha384':
            return self._handshakeSHA384.digest()
        elif digest == 'sha512':
            return self._handshakeSHA512.digest()
        else:
            raise ValueError("Unknown digest type")

    def digestSSL(self, masterSecret, label):
        """
        Calculate and return digest for already consumed data (SSLv3 version)

        Used for Finished and CertificateVerify messages.

        :param bytearray masterSecret: value of the master secret
        :param bytearray label: label to include in the calculation
        """
        md5_hash = MD5()
        md5_hash.update(label)
        md5_hash.update(masterSecret)
        md5_hash.update(compatHMAC(MD5(self._handshake_buffer).digest()))

        sha_hash = SHA1()
        sha_hash.update(label)
        sha_hash.update(masterSecret)
        sha_hash.update(compatHMAC(SHA1(self._handshake_buffer).digest()))

        return md5_hash.digest() + sha_hash.digest()

    def copy(self):
        """
        Copy object

        Return a copy of the object with all the hashes in the same state
        as the source object.

        :rtype: HandshakeHashes
        """
        new = HandshakeHashes()
        new._handshakeMD5 = self._handshakeMD5.copy()
        new._handshakeSHA = self._handshakeSHA.copy()
        new._handshakeSHA224 = self._handshakeSHA224.copy()
        new._handshakeSHA256 = self._handshakeSHA256.copy()
        new._handshakeSHA384 = self._handshakeSHA384.copy()
        new._handshakeSHA512 = self._handshakeSHA512.copy()
        new._handshake_buffer = self._handshake_buffer[:]
        return new
