"""Abstract class for DSA."""


class DSAKey(object):
    """This is an abstract base class for DSA keys.

    Particular implementations of DSA keys, such as
    :py:class:`~.python_dsakey.Python_DSAKey`
    ... more coming
    inherit from this.

    To create or parse an DSA key, don't use one of these classes
    directly.  Instead, use the factory functions in
    :py:class:`~tlslite.utils.keyfactory`.
    """

    def __init__(self, p, q, g, x, y):
        """Create a new DSA key.
        :type p: int
        :param p: domain parameter, prime num defining Gaolis Field
        :type q: int
        :param q: domain parameter, prime factor of p-1
        :type g: int
        :param g: domain parameter, generator of q-order cyclic group GP(p)
        :type x: int
        :param x: private key
        :type y: int
        :param y: public key
        """
        self.p = p
        self.q = q
        self.g = g
        self.x = x
        self.y = y

    def __len__(self):
        """Return the size of the order of the curve of this key, in bits.

        :rtype: int
        """
        return self.q.bit_length()

    def hasPrivateKey(self):
        """Return whether or not this key has a private component.

        :rtype: bool
        """
        return self.x is not None

    def hashAndSign(self, data, hAlg):
        """Hash and sign the passed-in bytes.

        This requires the key to have a private component and
        global parameters. It performs a signature on the passed-in data
        with selected hash algorithm.

        :type data: str
        :param data: The data which will be hashed and signed.

        :type hAlg: str
        :param hAlg: The hash algorithm that will be used to hash data

        :rtype: bytearray
        :returns: An DSA signature on the passed-in data.
        """
        import hashlib
        import random
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import dsa

        if not self.hasPrivateKey():
            raise ValueError("Private key is required for signing")

        # Hash the data
        hash_obj = getattr(hashlib, hAlg)()
        hash_obj.update(data.encode('utf-8'))
        hashed_data = hash_obj.digest()

        # Generate k (random number between 1 and q-1)
        k = random.randrange(1, self.q)

        # Calculate r = (g^k mod p) mod q
        r = pow(self.g, k, self.p) % self.q

        # Calculate s = (k^-1 * (H(m) + x*r)) mod q
        k_inv = pow(k, -1, self.q)
        s = (k_inv * (int.from_bytes(hashed_data, 'big') + self.x * r)) % self.q

        # Convert r and s to bytes and concatenate
        signature = r.to_bytes((r.bit_length() + 7) // 8, 'big') + s.to_bytes((s.bit_length() + 7) // 8, 'big')
        return bytearray(signature)

    def hashAndVerify(self, signature, data, hAlg='sha1'):
        """Hash and verify the passed-in bytes with signature.

        :type signature: ASN1 bytearray
        :param signature: the r, s dsa signature

        :type data: str
        :param data: The data which will be hashed and verified.

        :type hAlg: str
        :param hAlg: The hash algorithm that will be used to hash data

        :rtype: bool
        :returns: return True if verification is OK.
        """
        import hashlib

        # Hash the data
        hash_obj = getattr(hashlib, hAlg)()
        hash_obj.update(data.encode('utf-8'))
        hashed_data = hash_obj.digest()

        # Extract r and s from the signature
        signature_length = len(signature)
        r = int.from_bytes(signature[:signature_length//2], 'big')
        s = int.from_bytes(signature[signature_length//2:], 'big')

        if r <= 0 or r >= self.q or s <= 0 or s >= self.q:
            return False

        # Calculate w = s^-1 mod q
        w = pow(s, -1, self.q)

        # Calculate u1 = (H(m) * w) mod q
        u1 = (int.from_bytes(hashed_data, 'big') * w) % self.q

        # Calculate u2 = (r * w) mod q
        u2 = (r * w) % self.q

        # Calculate v = ((g^u1 * y^u2) mod p) mod q
        v = ((pow(self.g, u1, self.p) * pow(self.y, u2, self.p)) % self.p) % self.q

        return v == r

    @staticmethod
    def generate(L, N):
        """Generate new key given by bit lengths L, N.

        :type L: int
        :param L: length of parameter p in bits

        :type N: int
        :param N: length of parameter q in bits

        :rtype: DSAkey
        :returns: DSAkey(domain parameters, private key, public key)
        """
        from cryptography.hazmat.primitives.asymmetric import dsa
        from cryptography.hazmat.backends import default_backend

        # Generate the DSA parameters
        parameters = dsa.generate_parameters(key_size=L, backend=default_backend())

        # Generate a new DSA key pair
        private_key = parameters.generate_private_key()

        # Extract the components
        p = private_key.private_numbers().public_numbers.parameter_numbers.p
        q = private_key.private_numbers().public_numbers.parameter_numbers.q
        g = private_key.private_numbers().public_numbers.parameter_numbers.g
        x = private_key.private_numbers().x
        y = private_key.private_numbers().public_numbers.y

        return DSAKey(p, q, g, x, y)

    @staticmethod
    def generate_qp(L, N):
        """Generate new (p, q) given by bit lengths L, N.

        :type L: int
        :param L: length of parameter p in bits

        :type N: int
        :param N: length of parameter q in bits

        :rtype: (int, int)
        :returns: new p and q key parameters
        """
        from cryptography.hazmat.primitives.asymmetric import dsa
        from cryptography.hazmat.backends import default_backend

        # Generate the DSA parameters
        parameters = dsa.generate_parameters(key_size=L, backend=default_backend())

        # Extract p and q
        p = parameters.parameter_numbers().p
        q = parameters.parameter_numbers().q

        return (p, q)
