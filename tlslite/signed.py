"""Base class that represents any signed object"""
from .utils.cryptomath import numBytes
RSA_SIGNATURE_HASHES = ['sha512', 'sha384', 'sha256', 'sha224', 'sha1']
ALL_RSA_SIGNATURE_HASHES = RSA_SIGNATURE_HASHES + ['md5']
RSA_SCHEMES = ['pss', 'pkcs1']


class SignatureSettings(object):

    def __init__(self, min_key_size=None, max_key_size=None, rsa_sig_hashes
        =None, rsa_schemes=None):
        """Create default variables for key-related settings."""
        self.min_key_size = min_key_size or 1023
        self.max_key_size = max_key_size or 8193
        self.rsa_sig_hashes = rsa_sig_hashes or list(RSA_SIGNATURE_HASHES)
        self.rsa_schemes = rsa_schemes or list(RSA_SCHEMES)


class SignedObject(object):

    def __init__(self):
        self.tbs_data = None
        self.signature = None
        self.signature_alg = None
    _hash_algs_OIDs = {tuple([42, 134, 72, 134, 247, 13, 1, 1, 4]): 'md5',
        tuple([42, 134, 72, 134, 247, 13, 1, 1, 5]): 'sha1', tuple([42, 134,
        72, 134, 247, 13, 1, 1, 14]): 'sha224', tuple([42, 134, 72, 134, 
        247, 13, 1, 1, 12]): 'sha384', tuple([42, 134, 72, 134, 247, 13, 1,
        1, 11]): 'sha256', tuple([42, 134, 72, 134, 247, 13, 1, 1, 13]):
        'sha512'}

    def verify_signature(self, publicKey, settings=None):
        """Verify signature in a response"""
        if settings is None:
            settings = SignatureSettings()

        if not self.tbs_data or not self.signature or not self.signature_alg:
            return False

        hash_name = self._hash_algs_OIDs.get(tuple(self.signature_alg))
        if not hash_name:
            return False

        if hash_name not in settings.rsa_sig_hashes:
            return False

        key_size = numBytes(publicKey.n)
        if key_size < settings.min_key_size // 8 or key_size > settings.max_key_size // 8:
            return False

        for scheme in settings.rsa_schemes:
            if scheme == 'pss':
                if publicKey.verify(self.signature, self.tbs_data, hash_name, 'pss'):
                    return True
            elif scheme == 'pkcs1':
                if publicKey.verify(self.signature, self.tbs_data, hash_name):
                    return True

        return False
