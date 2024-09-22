"""Miscellaneous functions to mask Python version differences."""
import sys
import re
import os
import platform
import math
import binascii
import traceback
import time
import ecdsa
if sys.version_info >= (3, 0):
    if sys.version_info < (3, 4):

        def compatHMAC(x):
            """Convert bytes-like input to format acceptable for HMAC."""
            pass
    else:

        def compatHMAC(x):
            """Convert bytes-like input to format acceptable for HMAC."""
            pass

    def compatAscii2Bytes(val):
        """Convert ASCII string to bytes."""
        pass

    def compat_b2a(val):
        """Convert an ASCII bytes string to string."""
        pass
    int_types = tuple([int])

    def formatExceptionTrace(e):
        """Return exception information formatted as string"""
        pass

    def time_stamp():
        """Returns system time as a float"""
        pass

    def remove_whitespace(text):
        """Removes all whitespace from passed in string"""
        pass
    bytes_to_int = int.from_bytes

    def bit_length(val):
        """Return number of bits necessary to represent an integer."""
        pass

    def int_to_bytes(val, length=None, byteorder='big'):
        """Return number converted to bytes"""
        pass
else:
    if sys.version_info < (2, 7) or sys.version_info < (2, 7, 4
        ) or platform.system() == 'Java':

        def remove_whitespace(text):
            """Removes all whitespace from passed in string"""
            pass

        def bit_length(val):
            """Return number of bits necessary to represent an integer."""
            pass
    else:

        def remove_whitespace(text):
            """Removes all whitespace from passed in string"""
            pass

        def bit_length(val):
            """Return number of bits necessary to represent an integer."""
            pass

    def compatAscii2Bytes(val):
        """Convert ASCII string to bytes."""
        pass

    def compat_b2a(val):
        """Convert an ASCII bytes string to string."""
        pass
    int_types = int, long

    def formatExceptionTrace(e):
        """Return exception information formatted as string"""
        pass

    def time_stamp():
        """Returns system time as a float"""
        pass

    def bytes_to_int(val, byteorder):
        """Convert bytes to an int."""
        pass

    def int_to_bytes(val, length=None, byteorder='big'):
        """Return number converted to bytes"""
        pass


def byte_length(val):
    """Return number of bytes necessary to represent an integer."""
    pass


try:
    getattr(ecdsa, 'NIST192p')
except AttributeError:
    ecdsaAllCurves = False
else:
    ecdsaAllCurves = True
