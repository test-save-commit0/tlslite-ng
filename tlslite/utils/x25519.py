"""Handling X25519 and X448 curve based key agreement protocol."""
from .cryptomath import bytesToNumber, numberToByteArray, divceil


def decodeUCoordinate(u, bits):
    """Function to decode the public U coordinate of X25519-family curves."""
    pass


def decodeScalar22519(k):
    """Function to decode the private K parameter of the x25519 function."""
    pass


def decodeScalar448(k):
    """Function to decode the private K parameter of the X448 function."""
    pass


def cswap(swap, x_2, x_3):
    """Conditional swap function."""
    pass


X25519_G = numberToByteArray(9, 32, endian='little')
X25519_ORDER_SIZE = 32


def x25519(k, u):
    """
    Perform point multiplication on X25519 curve.

    :type k: bytearray
    :param k: random secret value (multiplier), should be 32 byte long

    :type u: bytearray
    :param u: curve generator or the other party key share

    :rtype: bytearray
    """
    pass


X448_G = numberToByteArray(5, 56, endian='little')
X448_ORDER_SIZE = 56


def x448(k, u):
    """
    Perform point multiplication on X448 curve.

    :type k: bytearray
    :param k: random secret value (multiplier), should be 56 bytes long

    :type u: bytearray
    :param u: curve generator or the other party key share

    :rtype: bytearray
    """
    pass


def _x25519_generic(k, u, bits, a24, p):
    """Generic Montgomery ladder implementation of the x25519 algorithm."""
    pass
