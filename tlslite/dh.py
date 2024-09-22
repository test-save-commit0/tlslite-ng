"""Handling of Diffie-Hellman parameter files."""
from .utils.asn1parser import ASN1Parser
from .utils.pem import dePem
from .utils.cryptomath import bytesToNumber


def parseBinary(data):
    """
    Parse DH parameters from ASN.1 DER encoded binary string.

    :param bytes data: DH parameters
    :rtype: tuple of int
    """
    pass


def parse(data):
    """
    Parses DH parameters from a binary string.

    The string can either by PEM or DER encoded

    :param bytes data: DH parameters
    :rtype: tuple of int
    :returns: generator and prime
    """
    pass
