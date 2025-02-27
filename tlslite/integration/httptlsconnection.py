"""TLS Lite + httplib."""
import socket
try:
    import httplib
except ImportError:
    from http import client as httplib
from tlslite.tlsconnection import TLSConnection
from tlslite.integration.clienthelper import ClientHelper


class HTTPTLSConnection(httplib.HTTPConnection, ClientHelper):
    """This class extends L{httplib.HTTPConnection} to support TLS."""

    def __init__(self, host, port=None, strict=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                 source_address=None, username=None, password=None, certChain=None,
                 privateKey=None, checker=None, settings=None, ignoreAbruptClose=False, anon=False):
        """Create a new HTTPTLSConnection.

        For client authentication, use one of these argument
        combinations:

          - username, password (SRP)
          - certChain, privateKey (certificate)

        For server authentication, you can either rely on the
        implicit mutual authentication performed by SRP
        or you can do certificate-based server
        authentication with one of these argument combinations:

          - x509Fingerprint

        Certificate-based server authentication is compatible with
        SRP or certificate-based client authentication.

        The constructor does not perform the TLS handshake itself, but
        simply stores these arguments for later.  The handshake is
        performed only when this class needs to connect with the
        server.  Thus you should be prepared to handle TLS-specific
        exceptions when calling methods inherited from
        :py:class:`httplib.HTTPConnection` such as request(), connect(), and
        send().  See the client handshake functions in
        :py:class:`~tlslite.tlsconnection.TLSConnection` for details on which
        exceptions might be raised.

        :type host: str
        :param host: Server to connect to.

        :type port: int
        :param port: Port to connect to.

        :type username: str
        :param username: SRP username.  Requires the
            'password' argument.

        :type password: str
        :param password: SRP password for mutual authentication.
            Requires the 'username' argument.

        :type certChain: ~tlslite.x509certchain.X509CertChain
        :param certChain: Certificate chain for client authentication.
            Requires the 'privateKey' argument.  Excludes the SRP arguments.

        :type privateKey: ~tlslite.utils.rsakey.RSAKey
        :param privateKey: Private key for client authentication.
            Requires the 'certChain' argument.  Excludes the SRP arguments.

        :type checker: ~tlslite.checker.Checker
        :param checker: Callable object called after handshaking to
            evaluate the connection and raise an Exception if necessary.

        :type settings: ~tlslite.handshakesettings.HandshakeSettings
        :param settings: Various settings which can be used to control
            the ciphersuites, certificate types, and SSL/TLS versions
            offered by the client.

        :type ignoreAbruptClose: bool
        :param ignoreAbruptClose: ignore the TLSAbruptCloseError on
            unexpected hangup.
        """
        if source_address:
            httplib.HTTPConnection.__init__(self, host=host, port=port,
                                            timeout=timeout, source_address=source_address)
        else:
            httplib.HTTPConnection.__init__(self, host=host, port=port,
                                            timeout=timeout)
        self.ignoreAbruptClose = ignoreAbruptClose
        ClientHelper.__init__(self, username, password, certChain,
                              privateKey, checker, settings, anon, host)
        self.tlsConnection = None

    def connect(self):
        """Connect to a host on a given (SSL) port."""
        httplib.HTTPConnection.connect(self)
        
        self.sock = TLSConnection(self.sock)
        
        try:
            self.start_tls()
            self.tlsConnection = self.sock
        except:
            self.close()
            raise

    def close(self):
        """Close the connection to the HTTP server."""
        if self.tlsConnection:
            self.tlsConnection.close()
        httplib.HTTPConnection.close(self)

    def send(self, data):
        """Send `data` to the server."""
        if self.tlsConnection:
            self.tlsConnection.send(data)
        else:
            httplib.HTTPConnection.send(self, data)

    def _tunnel(self):
        """Set up the tunnel to the server."""
        self.connect()
        httplib.HTTPConnection._tunnel(self)
