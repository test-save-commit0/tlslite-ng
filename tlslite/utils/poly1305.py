"""Implementation of Poly1305 authenticator for RFC 7539"""
from .cryptomath import divceil


class Poly1305(object):
    """Poly1305 authenticator"""
    P = 1361129467683753853853498429727072845819

    @staticmethod
    def le_bytes_to_num(data):
        """Convert a number from little endian byte format"""
        pass

    @staticmethod
    def num_to_16_le_bytes(num):
        """Convert number to 16 bytes in little endian format"""
        pass

    def __init__(self, key):
        """Set the authenticator key"""
        if len(key) != 32:
            raise ValueError('Key must be 256 bit long')
        self.acc = 0
        self.r = self.le_bytes_to_num(key[0:16])
        self.r &= 21267647620597763993911028882763415551
        self.s = self.le_bytes_to_num(key[16:32])

    def create_tag(self, data):
        """Calculate authentication tag for data"""
        pass
