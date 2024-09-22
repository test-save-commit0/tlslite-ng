"""hashlib that handles FIPS mode."""
from hashlib import *
import hashlib


def _fipsFunction(func, *args, **kwargs):
    """Make hash function support FIPS mode."""
    pass


def md5(*args, **kwargs):
    """MD5 constructor that works in FIPS mode."""
    pass


def new(*args, **kwargs):
    """General constructor that works in FIPS mode."""
    pass
