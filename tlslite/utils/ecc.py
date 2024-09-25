"""Methods for dealing with ECC points"""
import ecdsa
from .compat import ecdsaAllCurves


def getCurveByName(curveName):
    """Return curve identified by curveName"""
    for curve in ecdsaAllCurves:
        if curve.name == curveName:
            return curve
    raise ValueError(f"Curve {curveName} not found")


def getPointByteSize(point):
    """Convert the point or curve bit size to bytes"""
    if isinstance(point, ecdsa.ellipticcurve.Point):
        return (point.curve().p().bit_length() + 7) // 8
    elif isinstance(point, ecdsa.curves.Curve):
        return (point.p().bit_length() + 7) // 8
    else:
        raise TypeError("Input must be an elliptic curve point or curve")
