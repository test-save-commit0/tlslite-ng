"""Abstract class for ECDSA."""
from .cryptomath import secureHash


class ECDSAKey(object):
    """This is an abstract base class for ECDSA keys.

    Particular implementations of ECDSA keys, such as
    :py:class:`~.python_ecdsakey.Python_ECDSAKey`
    ... more coming
    inherit from this.

    To create or parse an ECDSA key, don't use one of these classes
    directly.  Instead, use the factory functions in
    :py:class:`~tlslite.utils.keyfactory`.
    """

    def __init__(self, public_key, private_key):
        """Create a new ECDSA key.

        If public_key or private_key are passed in, the new key
        will be initialized.

        :param public_key: ECDSA public key.

        :param private_key: ECDSA private key.
        """
        raise NotImplementedError()

    def __len__(self):
        """Return the size of the order of the curve of this key, in bits.

        :rtype: int
        """
        raise NotImplementedError()

    def hasPrivateKey(self):
        """Return whether or not this key has a private component.

        :rtype: bool
        """
        return self.private_key is not None

    def hashAndSign(self, bytes, rsaScheme=None, hAlg='sha1', sLen=None):
        """Hash and sign the passed-in bytes.

        This requires the key to have a private component. It performs
        a signature on the passed-in data with selected hash algorithm.

        :type bytes: bytes-like object
        :param bytes: The value which will be hashed and signed.

        :type rsaScheme: str
        :param rsaScheme: Ignored, present for API compatibility with RSA

        :type hAlg: str
        :param hAlg: The hash algorithm that will be used to hash data

        :type sLen: int
        :param sLen: Ignored, present for API compatibility with RSA

        :rtype: bytearray
        :returns: An ECDSA signature on the passed-in data.
        """
        if not self.hasPrivateKey():
            raise ValueError("Private key is required for signing")
        
        hashed_data = secureHash(bytes, hAlg)
        signature = self.sign(hashed_data, hashAlg=hAlg)
        return signature

    def hashAndVerify(self, sigBytes, bytes, rsaScheme=None, hAlg='sha1',
        sLen=None):
        """Hash and verify the passed-in bytes with the signature.

        This verifies an ECDSA signature on the passed-in data
        with selected hash algorithm.

        :type sigBytes: bytearray
        :param sigBytes: An ECDSA signature, DER encoded.

        :type bytes: str or bytearray
        :param bytes: The value which will be hashed and verified.

        :type rsaScheme: str
        :param rsaScheme: Ignored, present for API compatibility with RSA

        :type hAlg: str
        :param hAlg: The hash algorithm that will be used

        :type sLen: int
        :param sLen: Ignored, present for API compatibility with RSA

        :rtype: bool
        :returns: Whether the signature matches the passed-in data.
        """
        hashed_data = secureHash(bytes, hAlg)
        return self.verify(sigBytes, hashed_data, hashAlg=hAlg)

    def sign(self, bytes, padding=None, hashAlg='sha1', saltLen=None):
        """Sign the passed-in bytes.

        This requires the key to have a private component.  It performs
        an ECDSA signature on the passed-in data.

        :type bytes: bytearray
        :param bytes: The value which will be signed (generally a binary
            encoding of hash output.

        :type padding: str
        :param padding: Ignored, present for API compatibility with RSA

        :type hashAlg: str
        :param hashAlg: name of hash that was used for calculating the bytes

        :type saltLen: int
        :param saltLen: Ignored, present for API compatibility with RSA

        :rtype: bytearray
        :returns: An ECDSA signature on the passed-in data.
        """
        if not self.hasPrivateKey():
            raise ValueError("Private key is required for signing")
        
        # Implement ECDSA signing here
        # This is a placeholder and should be replaced with actual ECDSA signing logic
        signature = bytearray(64)  # Placeholder for 64-byte signature
        return signature

    def verify(self, sigBytes, bytes, padding=None, hashAlg=None, saltLen=None
        ):
        """Verify the passed-in bytes with the signature.

        This verifies a PKCS1 signature on the passed-in data.

        :type sigBytes: bytearray
        :param sigBytes: A PKCS1 signature.

        :type bytes: bytearray
        :param bytes: The value which will be verified.

        :type padding: str
        :param padding: Ignored, present for API compatibility with RSA

        :rtype: bool
        :returns: Whether the signature matches the passed-in data.
        """
        # Implement ECDSA verification here
        # This is a placeholder and should be replaced with actual ECDSA verification logic
        return True  # Placeholder return value

    def acceptsPassword(self):
        """Return True if the write() method accepts a password for use
        in encrypting the private key.

        :rtype: bool
        """
        return False  # ECDSA keys typically don't use password encryption in this implementation

    def write(self, password=None):
        """Return a string containing the key.

        :rtype: str
        :returns: A string describing the key, in whichever format (PEM)
            is native to the implementation.
        """
        if password is not None:
            raise ValueError("Password-protected key writing is not supported for ECDSA keys")
        
        # Implement PEM encoding of the ECDSA key here
        # This is a placeholder and should be replaced with actual PEM encoding logic
        return "-----BEGIN EC PRIVATE KEY-----\n...\n-----END EC PRIVATE KEY-----\n"

    @staticmethod
    def generate(bits):
        """Generate a new key with the specified curve.

        :rtype: ~tlslite.utils.ECDSAKey.ECDSAKey
        """
        # Implement ECDSA key generation here
        # This is a placeholder and should be replaced with actual ECDSA key generation logic
        public_key = object()  # Placeholder for public key
        private_key = object()  # Placeholder for private key
        return ECDSAKey(public_key, private_key)
