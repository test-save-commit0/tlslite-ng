from .compat import *
import binascii


def dePem(s, name):
    """Decode a PEM string into a bytearray of its payload.
    
    The input must contain an appropriate PEM prefix and postfix
    based on the input name string, e.g. for name="CERTIFICATE"::

      -----BEGIN CERTIFICATE-----
      MIIBXDCCAUSgAwIBAgIBADANBgkqhkiG9w0BAQUFADAPMQ0wCwYDVQQDEwRUQUNL
      ...
      KoZIhvcNAQEFBQADAwA5kw==
      -----END CERTIFICATE-----

    The first such PEM block in the input will be found, and its
    payload will be base64 decoded and returned.
    """
    start = s.find(f"-----BEGIN {name}-----")
    end = s.find(f"-----END {name}-----")
    if start == -1 or end == -1:
        raise ValueError(f"PEM block for {name} not found")
    
    start += len(f"-----BEGIN {name}-----")
    pem_data = s[start:end].strip()
    return bytearray(binascii.a2b_base64(pem_data))


def dePemList(s, name):
    """Decode a sequence of PEM blocks into a list of bytearrays.

    The input must contain any number of PEM blocks, each with the appropriate
    PEM prefix and postfix based on the input name string, e.g. for
    name="TACK BREAK SIG".  Arbitrary text can appear between and before and
    after the PEM blocks.  For example::

        Created by TACK.py 0.9.3 Created at 2012-02-01T00:30:10Z
        -----BEGIN TACK BREAK SIG-----
        ATKhrz5C6JHJW8BF5fLVrnQss6JnWVyEaC0p89LNhKPswvcC9/s6+vWLd9snYTUv
        YMEBdw69PUP8JB4AdqA3K6Ap0Fgd9SSTOECeAKOUAym8zcYaXUwpk0+WuPYa7Zmm
        SkbOlK4ywqt+amhWbg9txSGUwFO5tWUHT3QrnRlE/e3PeNFXLx5Bckg=
        -----END TACK BREAK SIG-----
        Created by TACK.py 0.9.3 Created at 2012-02-01T00:30:11Z
        -----BEGIN TACK BREAK SIG-----
        ATKhrz5C6JHJW8BF5fLVrnQss6JnWVyEaC0p89LNhKPswvcC9/s6+vWLd9snYTUv
        YMEBdw69PUP8JB4AdqA3K6BVCWfcjN36lx6JwxmZQncS6sww7DecFO/qjSePCxwM
        +kdDqX/9/183nmjx6bf0ewhPXkA0nVXsDYZaydN8rJU1GaMlnjcIYxY=
        -----END TACK BREAK SIG-----
    
    All such PEM blocks will be found, decoded, and return in an ordered list
    of bytearrays, which may have zero elements if not PEM blocks are found.
    """
    result = []
    start = 0
    while True:
        start = s.find(f"-----BEGIN {name}-----", start)
        if start == -1:
            break
        end = s.find(f"-----END {name}-----", start)
        if end == -1:
            break
        pem_block = s[start:end + len(f"-----END {name}-----")]
        result.append(dePem(pem_block, name))
        start = end + len(f"-----END {name}-----")
    return result


def pem(b, name):
    """Encode a payload bytearray into a PEM string.
    
    The input will be base64 encoded, then wrapped in a PEM prefix/postfix
    based on the name string, e.g. for name="CERTIFICATE"::
    
        -----BEGIN CERTIFICATE-----
        MIIBXDCCAUSgAwIBAgIBADANBgkqhkiG9w0BAQUFADAPMQ0wCwYDVQQDEwRUQUNL
        ...
        KoZIhvcNAQEFBQADAwA5kw==
        -----END CERTIFICATE-----
    """
    b64 = binascii.b2a_base64(b).decode('ascii').strip()
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {name}-----\n" + "\n".join(lines) + f"\n-----END {name}-----\n"
