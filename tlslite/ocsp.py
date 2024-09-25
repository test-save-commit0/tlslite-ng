"""Class for handling primary OCSP responses"""
from .utils.asn1parser import ASN1Parser
from .utils.cryptomath import bytesToNumber, numBytes, secureHash
from .x509 import X509
from .signed import SignedObject
from .errors import TLSIllegalParameterException


class OCSPRespStatus(object):
    """ OCSP response status codes (RFC 2560) """
    successful = 0
    malformedRequest = 1
    internalError = 2
    tryLater = 3
    sigRequired = 5
    unauthorized = 6


class CertStatus(object):
    """ Certificate status in an OCSP response """
    good, revoked, unknown = range(3)


class SingleResponse(object):
    """ This class represents SingleResponse ASN1 type (defined in RFC2560) """

    def __init__(self, value):
        self.value = value
        self.cert_hash_alg = None
        self.cert_issuer_name_hash = None
        self.cert_issuer_key_hash = None
        self.cert_serial_num = None
        self.cert_status = None
        self.this_update = None
        self.next_update = None
        self.parse(value)
    _hash_algs_OIDs = {tuple([42, 134, 72, 134, 247, 13, 2, 5]): 'md5',
        tuple([43, 14, 3, 2, 26]): 'sha1', tuple([96, 134, 72, 1, 101, 3, 4,
        2, 4]): 'sha224', tuple([96, 134, 72, 1, 101, 3, 4, 2, 1]):
        'sha256', tuple([96, 134, 72, 1, 101, 3, 4, 2, 2]): 'sha384', tuple
        ([96, 134, 72, 1, 101, 3, 4, 2, 3]): 'sha512'}


class OCSPResponse(SignedObject):
    """ This class represents an OCSP response. """

    def __init__(self, value):
        super(OCSPResponse, self).__init__()
        self.bytes = None
        self.resp_status = None
        self.resp_type = None
        self.version = None
        self.resp_id = None
        self.produced_at = None
        self.responses = []
        self.certs = []
        self.parse(value)

    def parse(self, value):
        """
        Parse a DER-encoded OCSP response.

        :type value: stream of bytes
        :param value: An DER-encoded OCSP response
        """
        self.bytes = value
        parser = ASN1Parser(value)

        self.resp_status = parser.getChild(0).value[0]
        if self.resp_status != OCSPRespStatus.successful:
            return

        response_bytes = parser.getChild(1).getChild(0)
        self.resp_type = response_bytes.getChild(0).value
        response_data = response_bytes.getChild(1)

        self._tbsdataparse(response_data.value)

    def _tbsdataparse(self, value):
        """
        Parse to be signed data,

        :type value: stream of bytes
        :param value: TBS data
        """
        parser = ASN1Parser(value)

        version = parser.getChild(0)
        if version.value != b'\x00':
            raise TLSIllegalParameterException("OCSP response version must be v1")
        self.version = 1

        self.resp_id = parser.getChild(1).value
        self.produced_at = parser.getChild(2).value

        responses = parser.getChild(3)
        for response in responses.children:
            self.responses.append(SingleResponse(response.value))

        if len(parser.children) > 4:
            certs = parser.getChild(4)
            for cert in certs.children:
                self.certs.append(X509().parse(cert.value))
