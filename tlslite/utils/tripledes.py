"""Abstract class for 3DES."""


class TripleDES(object):

    def __init__(self, key, mode, IV, implementation):
        if len(key) != 24:
            raise ValueError()
        if mode != 2:
            raise ValueError()
        if len(IV) != 8:
            raise ValueError()
        self.isBlockCipher = True
        self.isAEAD = False
        self.block_size = 8
        self.implementation = implementation
        self.name = '3des'
