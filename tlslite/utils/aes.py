"""Abstract class for AES."""


class AES(object):

    def __init__(self, key, mode, IV, implementation):
        if len(key) not in (16, 24, 32):
            raise AssertionError()
        if mode not in [2, 6]:
            raise AssertionError()
        if mode == 2:
            if len(IV) != 16:
                raise AssertionError()
        if mode == 6:
            if len(IV) > 16:
                raise AssertionError()
        self.isBlockCipher = True
        self.isAEAD = False
        self.block_size = 16
        self.implementation = implementation
        if len(key) == 16:
            self.name = 'aes128'
        elif len(key) == 24:
            self.name = 'aes192'
        elif len(key) == 32:
            self.name = 'aes256'
        else:
            raise AssertionError()
