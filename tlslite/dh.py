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
    parser = ASN1Parser(data)
    sequence = parser.getChild()
    p = bytesToNumber(sequence.getChildBytes(0))
    g = bytesToNumber(sequence.getChildBytes(1))
    return (p, g)


def parse(data):
    """
    Parses DH parameters from a binary string.

    The string can either by PEM or DER encoded

    :param bytes data: DH parameters
    :rtype: tuple of int
    :returns: generator and prime
    """
    try:
        der = dePem(data, "DH PARAMETERS")
    except ValueError:
        der = data

    return parseBinary(der)
