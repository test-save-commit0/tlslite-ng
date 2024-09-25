"""Various constant time functions for processing sensitive data"""
from __future__ import division
from .compat import compatHMAC
import hmac


def ct_lt_u32(val_a, val_b):
    """
    Returns 1 if val_a < val_b, 0 otherwise. Constant time.

    :type val_a: int
    :type val_b: int
    :param val_a: an unsigned integer representable as a 32 bit value
    :param val_b: an unsigned integer representable as a 32 bit value
    :rtype: int
    """
    return int((val_a - val_b) >> 31 & 1)


def ct_gt_u32(val_a, val_b):
    """
    Return 1 if val_a > val_b, 0 otherwise. Constant time.

    :type val_a: int
    :type val_b: int
    :param val_a: an unsigned integer representable as a 32 bit value
    :param val_b: an unsigned integer representable as a 32 bit value
    :rtype: int
    """
    return int((val_b - val_a) >> 31 & 1)


def ct_le_u32(val_a, val_b):
    """
    Return 1 if val_a <= val_b, 0 otherwise. Constant time.

    :type val_a: int
    :type val_b: int
    :param val_a: an unsigned integer representable as a 32 bit value
    :param val_b: an unsigned integer representable as a 32 bit value
    :rtype: int
    """
    return 1 - ct_gt_u32(val_a, val_b)


def ct_lsb_prop_u8(val):
    """Propagate LSB to all 8 bits of the returned int. Constant time."""
    return (val & 1) * 0xFF


def ct_lsb_prop_u16(val):
    """Propagate LSB to all 16 bits of the returned int. Constant time."""
    return (val & 1) * 0xFFFF


def ct_isnonzero_u32(val):
    """
    Returns 1 if val is != 0, 0 otherwise. Constant time.

    :type val: int
    :param val: an unsigned integer representable as a 32 bit value
    :rtype: int
    """
    return int((val | -val) >> 31 & 1)


def ct_neq_u32(val_a, val_b):
    """
    Return 1 if val_a != val_b, 0 otherwise. Constant time.

    :type val_a: int
    :type val_b: int
    :param val_a: an unsigned integer representable as a 32 bit value
    :param val_b: an unsigned integer representable as a 32 bit value
    :rtype: int
    """
    return ct_isnonzero_u32(val_a ^ val_b)


def ct_eq_u32(val_a, val_b):
    """
    Return 1 if val_a == val_b, 0 otherwise. Constant time.

    :type val_a: int
    :type val_b: int
    :param val_a: an unsigned integer representable as a 32 bit value
    :param val_b: an unsigned integer representable as a 32 bit value
    :rtype: int
    """
    return 1 - ct_neq_u32(val_a, val_b)


def ct_check_cbc_mac_and_pad(data, mac, seqnumBytes, contentType, version,
    block_size=16):
    """
    Check CBC cipher HMAC and padding. Close to constant time.

    :type data: bytearray
    :param data: data with HMAC value to test and padding

    :type mac: hashlib mac
    :param mac: empty HMAC, initialised with a key

    :type seqnumBytes: bytearray
    :param seqnumBytes: TLS sequence number, used as input to HMAC

    :type contentType: int
    :param contentType: a single byte, used as input to HMAC

    :type version: tuple of int
    :param version: a tuple of two ints, used as input to HMAC and to guide
        checking of padding

    :rtype: boolean
    :returns: True if MAC and pad is ok, False otherwise
    """
    data_len = len(data)
    mac_size = mac.digest_size
    pad_size = data[-1]
    
    # Check if the padding size is valid
    if pad_size == 0 or pad_size > block_size:
        return False

    # Calculate the start of padding
    pad_start = data_len - pad_size

    # Check if there's enough data for padding and MAC
    if pad_start < mac_size:
        return False

    # Verify padding
    for i in range(pad_start, data_len):
        if data[i] != pad_size:
            return False

    # Calculate MAC
    mac.update(seqnumBytes)
    mac.update(bytearray([contentType]))
    mac.update(bytearray([version[0], version[1]]))
    mac.update(bytearray([data_len - pad_size - mac_size >> 8]))
    mac.update(bytearray([data_len - pad_size - mac_size & 0xFF]))
    mac.update(data[:data_len - pad_size - mac_size])
    calculated_mac = mac.digest()

    # Compare MACs in constant time
    return ct_compare_digest(calculated_mac, data[data_len - pad_size - mac_size:data_len - pad_size])


if hasattr(hmac, 'compare_digest'):
    ct_compare_digest = hmac.compare_digest
else:

    def ct_compare_digest(val_a, val_b):
        """Compares if string like objects are equal. Constant time."""
        if len(val_a) != len(val_b):
            return False
        result = 0
        for x, y in zip(val_a, val_b):
            result |= x ^ y
        return result == 0
