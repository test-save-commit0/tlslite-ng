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
        pass

    def digest(self, digest=None):
        """
        Calculate and return digest for the already consumed data.

        Used for Finished and CertificateVerify messages.

        :param str digest: name of digest to return
        """
        pass

    def digestSSL(self, masterSecret, label):
        """
        Calculate and return digest for already consumed data (SSLv3 version)

        Used for Finished and CertificateVerify messages.

        :param bytearray masterSecret: value of the master secret
        :param bytearray label: label to include in the calculation
        """
        pass

    def copy(self):
        """
        Copy object

        Return a copy of the object with all the hashes in the same state
        as the source object.

        :rtype: HandshakeHashes
        """
        pass
