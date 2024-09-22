"""
Class initialization
--------------------
pyDes.Des(key, iv)
pyDes.Python_TripleDES(key, iv)

key -> Bytes containing the encryption key. 8 bytes for DES, 16 or 24 bytes
       for Triple DES
iv  -> Initialization Vector in bytes. Length must be 8 bytes.
"""
import sys
import warnings
PY_VER = sys.version_info


def new(key, iv):
    """Operate this 3DES cipher."""
    pass


class _baseDes(object):
    """The base class shared by DES and triple DES."""

    def __init__(self, iv):
        self.iv = iv

    def _guard_against_unicode(self, data):
        """Check the data for valid datatype and return them.

        Only accept byte strings or ascii unicode values.
        Otherwise there is no way to correctly decode the data into bytes.
        """
        pass


class Des(_baseDes):
    """DES encryption/decryption class.

    Supports CBC (Cypher Block Chaining) mode.
    """
    __pc1 = [56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17, 9, 1, 58,
        50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 62, 54, 46, 38, 30, 22, 
        14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 60, 52, 44, 36, 28, 20, 12, 4,
        27, 19, 11, 3]
    __left_rotations = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    __pc2 = [13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11, 3, 25, 
        7, 15, 6, 26, 19, 12, 1, 40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32,
        47, 43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31]
    __ip = [57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61,
        53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7, 56, 48, 
        40, 32, 24, 16, 8, 0, 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36,
        28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6]
    __expansion_table = [31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8, 7, 8, 9, 10, 
        11, 12, 11, 12, 13, 14, 15, 16, 15, 16, 17, 18, 19, 20, 19, 20, 21,
        22, 23, 24, 23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0]
    __sbox = [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15,
        7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 
        2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 
        3, 14, 10, 0, 6, 13], [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 
        0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 
        14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3,
        15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9], [10, 0, 9, 14, 6, 3, 15, 5, 1,
        13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 
        11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1,
        10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12], [7, 13, 14, 3, 
        0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 
        4, 7, 2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14,
        5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 
        12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 
        8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0,
        9, 10, 4, 5, 3], [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5,
        11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15,
        5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 
        10, 11, 14, 1, 7, 6, 0, 8, 13], [4, 11, 2, 14, 15, 0, 8, 13, 3, 12,
        9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 
        8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 
        13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12], [13, 2, 8, 4, 6, 15,
        11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5,
        6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3,
        5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
    __p = [15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9, 1, 7,
        23, 13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3, 24]
    __fp = [39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 
        37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3,
        43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9,
        49, 17, 57, 25, 32, 0, 40, 8, 48, 16, 56, 24]
    ENCRYPT = 0
    DECRYPT = 1

    def __init__(self, key, iv=None):
        if len(key) != 8:
            raise ValueError(
                'Invalid DES key size. Key must be exactly 8 bytes long')
        super(Des, self).__init__(iv)
        self.key_size = 8
        self._l = []
        self._r = []
        self._kn = [[0] * 48] * 16
        self._final = []
        self.set_key(key)

    def set_key(self, key):
        """Set the crypting key for this object. Must be 8 bytes."""
        pass

    def __string_to_bitlist(self, data):
        """Turn the string data into a list of bits (1, 0)'s."""
        pass

    def __bitlist_to_string(self, data):
        """Turn the data as list of bits into a string."""
        pass

    def __permutate(self, table, block):
        """Permutate this block with the specified table."""
        pass

    def __create_sub_keys(self):
        """Transform the secret key for data processing.

        Create the 16 subkeys k[1] to k[16] from the given key.
        """
        pass

    def __des_crypt(self, block, crypt_type):
        """Crypt the block of data through DES bit-manipulation."""
        pass

    def crypt(self, data, crypt_type):
        """Crypt the data in blocks, running it through des_crypt()."""
        pass


class Python_TripleDES(_baseDes):
    """Triple DES encryption/decrytpion class.

    This algorithm uses the DES-EDE3 (when a 24 byte key is supplied) or
    the DES-EDE2 (when a 16 byte key is supplied) encryption methods.
    Supports CBC (Cypher Block Chaining) mode.
    """

    def __init__(self, key, iv=None):
        self.block_size = 8
        if iv:
            if len(iv) != self.block_size:
                raise ValueError(
                    'Invalid Initialization Vector (iv) must be {0} bytes long'
                    .format(self.block_size))
            iv = self._guard_against_unicode(iv)
        else:
            raise ValueError('Initialization Vector (iv) must be supplied')
        super(Python_TripleDES, self).__init__(iv)
        self.key_size = len(key)
        if self.key_size not in (16, 24):
            raise ValueError(
                'Invalid triple DES key size. Key must be either 16 or 24 bytes long'
                )
        key = self._guard_against_unicode(key)
        self.__key1 = Des(key[:8], self.iv)
        self.__key2 = Des(key[8:16], self.iv)
        if self.key_size == 16:
            self.__key3 = Des(key[:8], self.iv)
        else:
            self.__key3 = Des(key[16:], self.iv)
        self.isAEAD = False
        self.isBlockCipher = True
        self.name = '3des'
        self.implementation = 'python'
        self.__key1.iv = self.iv
        self.__key2.iv = self.iv
        self.__key3.iv = self.iv

    def encrypt(self, data):
        """Encrypt data and return bytes.

        data : bytes to be encrypted

        The data must be a multiple of 8 bytes and will be encrypted
        with the already specified key.
        """
        pass

    def decrypt(self, data):
        """Decrypt data and return bytes.

        data : bytes to be encrypted

        The data must be a multiple of 8 bytes and will be decrypted
        with the already specified key.
        """
        pass
