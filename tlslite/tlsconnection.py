"""
MAIN CLASS FOR TLS LITE (START HERE!).
"""
from __future__ import division
import time
import socket
from itertools import chain
from .utils.compat import formatExceptionTrace
from .tlsrecordlayer import TLSRecordLayer
from .session import Session, Ticket
from .constants import *
from .utils.cryptomath import derive_secret, getRandomBytes, HKDF_expand_label
from .utils.dns_utils import is_valid_hostname
from .utils.lists import getFirstMatching
from .errors import *
from .messages import *
from .mathtls import *
from .handshakesettings import HandshakeSettings, KNOWN_VERSIONS, CURVE_ALIASES
from .handshakehashes import HandshakeHashes
from .utils.tackwrapper import *
from .utils.deprecations import deprecated_params
from .keyexchange import KeyExchange, RSAKeyExchange, DHE_RSAKeyExchange, ECDHE_RSAKeyExchange, SRPKeyExchange, ADHKeyExchange, AECDHKeyExchange, FFDHKeyExchange, ECDHKeyExchange
from .handshakehelpers import HandshakeHelpers
from .utils.cipherfactory import createAESCCM, createAESCCM_8, createAESGCM, createCHACHA20


class TLSConnection(TLSRecordLayer):
    """
    This class wraps a socket and provides TLS handshaking and data transfer.

    To use this class, create a new instance, passing a connected
    socket into the constructor.  Then call some handshake function.
    If the handshake completes without raising an exception, then a TLS
    connection has been negotiated.  You can transfer data over this
    connection as if it were a socket.

    This class provides both synchronous and asynchronous versions of
    its key functions.  The synchronous versions should be used when
    writing single-or multi-threaded code using blocking sockets.  The
    asynchronous versions should be used when performing asynchronous,
    event-based I/O with non-blocking sockets.

    Asynchronous I/O is a complicated subject; typically, you should
    not use the asynchronous functions directly, but should use some
    framework like asyncore or Twisted which TLS Lite integrates with
    (see
    :py:class:`~.integration.tlsasyncdispatchermixin.TLSAsyncDispatcherMixIn`).
    """

    def __init__(self, sock):
        """Create a new TLSConnection instance.

        :param sock: The socket data will be transmitted on.  The
            socket should already be connected.  It may be in blocking or
            non-blocking mode.

        :type sock: socket.socket
        """
        TLSRecordLayer.__init__(self, sock)
        self.serverSigAlg = None
        self.ecdhCurve = None
        self.dhGroupSize = None
        self.extendedMasterSecret = False
        self._clientRandom = bytearray(0)
        self._serverRandom = bytearray(0)
        self.next_proto = None
        self._ccs_sent = False
        self._peer_record_size_limit = None
        self._pha_supported = False

    def keyingMaterialExporter(self, label, length=20):
        """Return keying material as described in RFC 5705

        :type label: bytearray
        :param label: label to be provided for the exporter

        :type length: int
        :param length: number of bytes of the keying material to export
        """
        pass

    @deprecated_params({'async_': 'async'},
        "'{old_name}' is a keyword in Python 3.7, use'{new_name}'")
    def handshakeClientAnonymous(self, session=None, settings=None, checker
        =None, serverName=None, async_=False):
        """Perform an anonymous handshake in the role of client.

        This function performs an SSL or TLS handshake using an
        anonymous Diffie Hellman ciphersuite.

        Like any handshake function, this can be called on a closed
        TLS connection, or on a TLS connection that is already open.
        If called on an open connection it performs a re-handshake.

        If the function completes without raising an exception, the
        TLS connection will be open and available for data transfer.

        If an exception is raised, the connection will have been
        automatically closed (if it was ever open).

        :type session: ~tlslite.session.Session
        :param session: A TLS session to attempt to resume.  If the
            resumption does not succeed, a full handshake will be
            performed.

        :type settings: ~tlslite.handshakesettings.HandshakeSettings
        :param settings: Various settings which can be used to control
            the ciphersuites, certificate types, and SSL/TLS versions
            offered by the client.

        :type checker: ~tlslite.checker.Checker
        :param checker: A Checker instance.  This instance will be
            invoked to examine the other party's authentication
            credentials, if the handshake completes succesfully.

        :type serverName: string
        :param serverName: The ServerNameIndication TLS Extension.

        :type async_: bool
        :param async_: If False, this function will block until the
            handshake is completed.  If True, this function will return a
            generator.  Successive invocations of the generator will
            return 0 if it is waiting to read from the socket, 1 if it is
            waiting to write to the socket, or will raise StopIteration if
            the handshake operation is completed.

        :rtype: None or an iterable
        :returns: If 'async_' is True, a generator object will be
            returned.

        :raises socket.error: If a socket error occurs.
        :raises tlslite.errors.TLSAbruptCloseError: If the socket is closed
            without a preceding alert.
        :raises tlslite.errors.TLSAlert: If a TLS alert is signalled.
        :raises tlslite.errors.TLSAuthenticationError: If the checker
            doesn't like the other party's authentication credentials.
        """
        pass

    @deprecated_params({'async_': 'async'},
        "'{old_name}' is a keyword in Python 3.7, use'{new_name}'")
    def handshakeClientSRP(self, username, password, session=None, settings
        =None, checker=None, reqTack=True, serverName=None, async_=False):
        """Perform an SRP handshake in the role of client.

        This function performs a TLS/SRP handshake.  SRP mutually
        authenticates both parties to each other using only a
        username and password.  This function may also perform a
        combined SRP and server-certificate handshake, if the server
        chooses to authenticate itself with a certificate chain in
        addition to doing SRP.

        If the function completes without raising an exception, the
        TLS connection will be open and available for data transfer.

        If an exception is raised, the connection will have been
        automatically closed (if it was ever open).

        :type username: bytearray
        :param username: The SRP username.

        :type password: bytearray
        :param password: The SRP password.

        :type session: ~tlslite.session.Session
        :param session: A TLS session to attempt to resume.  This
            session must be an SRP session performed with the same username
            and password as were passed in.  If the resumption does not
            succeed, a full SRP handshake will be performed.

        :type settings: ~tlslite.handshakesettings.HandshakeSettings
        :param settings: Various settings which can be used to control
            the ciphersuites, certificate types, and SSL/TLS versions
            offered by the client.

        :type checker: ~tlslite.checker.Checker
        :param checker: A Checker instance.  This instance will be
            invoked to examine the other party's authentication
            credentials, if the handshake completes succesfully.

        :type reqTack: bool
        :param reqTack: Whether or not to send a "tack" TLS Extension,
            requesting the server return a TackExtension if it has one.

        :type serverName: string
        :param serverName: The ServerNameIndication TLS Extension.

        :type async_: bool
        :param async_: If False, this function will block until the
            handshake is completed.  If True, this function will return a
            generator.  Successive invocations of the generator will
            return 0 if it is waiting to read from the socket, 1 if it is
            waiting to write to the socket, or will raise StopIteration if
            the handshake operation is completed.

        :rtype: None or an iterable
        :returns: If 'async_' is True, a generator object will be
            returned.

        :raises socket.error: If a socket error occurs.
        :raises tlslite.errors.TLSAbruptCloseError: If the socket is closed
            without a preceding alert.
        :raises tlslite.errors.TLSAlert: If a TLS alert is signalled.
        :raises tlslite.errors.TLSAuthenticationError: If the checker
            doesn't like the other party's authentication credentials.
        """
        pass

    @deprecated_params({'async_': 'async'},
        "'{old_name}' is a keyword in Python 3.7, use'{new_name}'")
    def handshakeClientCert(self, certChain=None, privateKey=None, session=
        None, settings=None, checker=None, nextProtos=None, reqTack=True,
        serverName=None, async_=False, alpn=None):
        """Perform a certificate-based handshake in the role of client.

        This function performs an SSL or TLS handshake.  The server
        will authenticate itself using an X.509 certificate
        chain.  If the handshake succeeds, the server's certificate
        chain will be stored in the session's serverCertChain attribute.
        Unless a checker object is passed in, this function does no
        validation or checking of the server's certificate chain.

        If the server requests client authentication, the
        client will send the passed-in certificate chain, and use the
        passed-in private key to authenticate itself.  If no
        certificate chain and private key were passed in, the client
        will attempt to proceed without client authentication.  The
        server may or may not allow this.

        If the function completes without raising an exception, the
        TLS connection will be open and available for data transfer.

        If an exception is raised, the connection will have been
        automatically closed (if it was ever open).

        :type certChain: ~tlslite.x509certchain.X509CertChain
        :param certChain: The certificate chain to be used if the
            server requests client authentication.

        :type privateKey: ~tlslite.utils.rsakey.RSAKey
        :param privateKey: The private key to be used if the server
            requests client authentication.

        :type session: ~tlslite.session.Session
        :param session: A TLS session to attempt to resume.  If the
            resumption does not succeed, a full handshake will be
            performed.

        :type settings: ~tlslite.handshakesettings.HandshakeSettings
        :param settings: Various settings which can be used to control
            the ciphersuites, certificate types, and SSL/TLS versions
            offered by the client.

        :type checker: ~tlslite.checker.Checker
        :param checker: A Checker instance.  This instance will be
            invoked to examine the other party's authentication
            credentials, if the handshake completes succesfully.

        :type nextProtos: list of str
        :param nextProtos: A list of upper layer protocols ordered by
            preference, to use in the Next-Protocol Negotiation Extension.

        :type reqTack: bool
        :param reqTack: Whether or not to send a "tack" TLS Extension,
            requesting the server return a TackExtension if it has one.

        :type serverName: string
        :param serverName: The ServerNameIndication TLS Extension.

        :type async_: bool
        :param async_: If False, this function will block until the
            handshake is completed.  If True, this function will return a
            generator.  Successive invocations of the generator will
            return 0 if it is waiting to read from the socket, 1 if it is
            waiting to write to the socket, or will raise StopIteration if
            the handshake operation is completed.

        :type alpn: list of bytearrays
        :param alpn: protocol names to advertise to server as supported by
            client in the Application Layer Protocol Negotiation extension.
            Example items in the array include b'http/1.1' or b'h2'.

        :rtype: None or an iterable
        :returns: If 'async_' is True, a generator object will be
            returned.

        :raises socket.error: If a socket error occurs.
        :raises tlslite.errors.TLSAbruptCloseError: If the socket is closed
            without a preceding alert.
        :raises tlslite.errors.TLSAlert: If a TLS alert is signalled.
        :raises tlslite.errors.TLSAuthenticationError: If the checker
            doesn't like the other party's authentication credentials.
        """
        pass

    @staticmethod
    def _getKEX(group, version):
        """Get object for performing key exchange."""
        pass

    @classmethod
    def _genKeyShareEntry(cls, group, version):
        """Generate KeyShareEntry object from randomly selected private value.
        """
        pass

    @staticmethod
    def _getPRFParams(cipher_suite):
        """Return name of hash used for PRF and the hash output size."""
        pass

    def _clientTLS13Handshake(self, settings, session, clientHello,
        clientCertChain, privateKey, serverHello):
        """Perform TLS 1.3 handshake as a client."""
        pass

    def _clientKeyExchange(self, settings, cipherSuite, clientCertChain,
        privateKey, certificateType, tackExt, clientRandom, serverRandom,
        keyExchange):
        """Perform the client side of key exchange"""
        pass

    def _check_certchain_with_settings(self, cert_chain, settings):
        """
        Verify that the key parameters match enabled ones.

        Checks if the certificate key size matches the minimum and maximum
        sizes set or that it uses curves enabled in settings
        """
        pass

    def handshakeServer(self, verifierDB=None, certChain=None, privateKey=
        None, reqCert=False, sessionCache=None, settings=None, checker=None,
        reqCAs=None, tacks=None, activationFlags=0, nextProtos=None, anon=
        False, alpn=None, sni=None):
        """Perform a handshake in the role of server.

        This function performs an SSL or TLS handshake.  Depending on
        the arguments and the behavior of the client, this function can
        perform an SRP, or certificate-based handshake.  It
        can also perform a combined SRP and server-certificate
        handshake.

        Like any handshake function, this can be called on a closed
        TLS connection, or on a TLS connection that is already open.
        If called on an open connection it performs a re-handshake.
        This function does not send a Hello Request message before
        performing the handshake, so if re-handshaking is required,
        the server must signal the client to begin the re-handshake
        through some other means.

        If the function completes without raising an exception, the
        TLS connection will be open and available for data transfer.

        If an exception is raised, the connection will have been
        automatically closed (if it was ever open).

        :type verifierDB: ~tlslite.verifierdb.VerifierDB
        :param verifierDB: A database of SRP password verifiers
            associated with usernames.  If the client performs an SRP
            handshake, the session's srpUsername attribute will be set.

        :type certChain: ~tlslite.x509certchain.X509CertChain
        :param certChain: The certificate chain to be used if the
            client requests server certificate authentication and no virtual
            host defined in HandshakeSettings matches ClientHello.

        :type privateKey: ~tlslite.utils.rsakey.RSAKey
        :param privateKey: The private key to be used if the client
            requests server certificate authentication and no virtual host
            defined in HandshakeSettings matches ClientHello.

        :type reqCert: bool
        :param reqCert: Whether to request client certificate
            authentication.  This only applies if the client chooses server
            certificate authentication; if the client chooses SRP
            authentication, this will be ignored.  If the client
            performs a client certificate authentication, the sessions's
            clientCertChain attribute will be set.

        :type sessionCache: ~tlslite.sessioncache.SessionCache
        :param sessionCache: An in-memory cache of resumable sessions.
            The client can resume sessions from this cache.  Alternatively,
            if the client performs a full handshake, a new session will be
            added to the cache.

        :type settings: ~tlslite.handshakesettings.HandshakeSettings
        :param settings: Various settings which can be used to control
            the ciphersuites and SSL/TLS version chosen by the server.

        :type checker: ~tlslite.checker.Checker
        :param checker: A Checker instance.  This instance will be
            invoked to examine the other party's authentication
            credentials, if the handshake completes succesfully.

        :type reqCAs: list of bytearray
        :param reqCAs: A collection of DER-encoded DistinguishedNames that
            will be sent along with a certificate request to help client pick
            a certificates. This does not affect verification.

        :type nextProtos: list of str
        :param nextProtos: A list of upper layer protocols to expose to the
            clients through the Next-Protocol Negotiation Extension,
            if they support it. Deprecated, use the `virtual_hosts` in
            HandshakeSettings.

        :type alpn: list of bytearray
        :param alpn: names of application layer protocols supported.
            Note that it will be used instead of NPN if both were advertised by
            client. Deprecated, use the `virtual_hosts` in HandshakeSettings.

        :type sni: bytearray
        :param sni: expected virtual name hostname. Deprecated, use the
            `virtual_hosts` in HandshakeSettings.

        :raises socket.error: If a socket error occurs.
        :raises tlslite.errors.TLSAbruptCloseError: If the socket is closed
            without a preceding alert.
        :raises tlslite.errors.TLSAlert: If a TLS alert is signalled.
        :raises tlslite.errors.TLSAuthenticationError: If the checker
            doesn't like the other party's authentication credentials.
        """
        pass

    def handshakeServerAsync(self, verifierDB=None, certChain=None,
        privateKey=None, reqCert=False, sessionCache=None, settings=None,
        checker=None, reqCAs=None, tacks=None, activationFlags=0,
        nextProtos=None, anon=False, alpn=None, sni=None):
        """Start a server handshake operation on the TLS connection.

        This function returns a generator which behaves similarly to
        handshakeServer().  Successive invocations of the generator
        will return 0 if it is waiting to read from the socket, 1 if it is
        waiting to write to the socket, or it will raise StopIteration
        if the handshake operation is complete.

        :rtype: iterable
        :returns: A generator; see above for details.
        """
        pass

    def request_post_handshake_auth(self, settings=None):
        """
        Request Post-handshake Authentication from client.

        The PHA process is asynchronous, and client may send some data before
        its certificates are added to Session object. Calling this generator
        will only request for the new identity of client, it will not wait for
        it.
        """
        pass

    @staticmethod
    def _derive_key_iv(nonce, user_key, settings):
        """Derive the IV and key for session ticket encryption."""
        pass

    def _serverSendTickets(self, settings):
        """Send session tickets to client."""
        pass

    def _serverTLS13Handshake(self, settings, clientHello, cipherSuite,
        privateKey, serverCertChain, version, scheme, srv_alpns, reqCert):
        """Perform a TLS 1.3 handshake"""
        pass

    def _serverSRPKeyExchange(self, clientHello, serverHello, verifierDB,
        cipherSuite, privateKey, serverCertChain, settings):
        """Perform the server side of SRP key exchange"""
        pass

    def _server_select_certificate(self, settings, client_hello,
        cipher_suites, cert_chain, private_key, version):
        """
        This method makes the decision on which certificate/key pair,
        signature algorithm and cipher to use based on the certificate.
        """
        pass

    @staticmethod
    def _pickServerKeyExchangeSig(settings, clientHello, certList=None,
        private_key=None, version=(3, 3), check_alt=True):
        """Pick a hash that matches most closely the supported ones"""
        pass

    @staticmethod
    def _sigHashesToList(settings, privateKey=None, certList=None, version=
        (3, 3)):
        """Convert list of valid signature hashes to array of tuples"""
        pass

    @staticmethod
    def _curveNamesToList(settings):
        """Convert list of acceptable curves to array identifiers"""
        pass

    @staticmethod
    def _groupNamesToList(settings):
        """Convert list of acceptable ff groups to TLS identifiers."""
        pass

    @staticmethod
    def _curve_name_to_hash_name(curve_name):
        """Returns the matching hash for a given curve name, for TLS 1.3

        expects the python-ecdsa curve names as parameter
        """
        pass
