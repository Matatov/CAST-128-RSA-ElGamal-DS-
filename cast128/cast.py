from s_boxes import *

rounds = 12
block_size = 64
key_size = 128
mode = 'CBC'


class Cast5:

    def __init__(self, rounds, bllock_size, key_size, mode, key):
        self.key = key
        self.key_size = key_size
        self.mode = mode
        self.rounds = rounds
        self.block_size = bllock_size

    def compute_subkeys(self):
        keys = []
        return keys

    def divide_plain_text(self, ptext):
        blocks = []
        return blocks

    def split(self, block):
        L = ''
        R = ''
        return L, R

    def round(self, L, R, subkey, ):
        """
        Calculate the round key using the key schedule.
        XOR the round key with the left half of the block.
        Calculate the new value for the left half of the block using the F function.
        Swap the left and right halves of the block.

        """

    def encrypt(self, ptext):
        ctext = ''
        round_keys = self.compute_subkeys()
        blocks = self.divide_plain_text(ptext)
        for i, block in enumerate(blocks):
            L, R = self.split(block)
            key = round_keys[i]
            temp = key ^ L
            L = f1(R, )
        return ctext


def f1(I, m, r):
    I = m + I
    I = I << r | I >> (32 - r)
    return s1[(I >> 24) & 0xff] ^ s2[(I >> 16) & 0xFF] - s3[(I >> 8) & 0xFF] + s4[I & 0xFF]


def f3(I, m, r):
    I = m + I
    I = I << r | I >> (32 - r)
    return s1[(I >> 24) & 0xff] - s2[(I >> 16) & 0xFF] + s3[(I >> 8) & 0xFF] ^ s4[I & 0xFF]


def f4(I, m, r):
    I = m + I
    I = I << r | I >> (32 - r)
    return s1[(I >> 24) & 0xff] + s2[(I >> 16) & 0xFF] ^ s3[(I >> 8) & 0xFF] - s4[I & 0xFF]
