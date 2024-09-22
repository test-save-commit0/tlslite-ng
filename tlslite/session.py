"""Class representing a TLS session."""
from .utils.compat import *
from .mathtls import *
from .constants import *


class Session(object):
    """
    This class represents a TLS session.

    TLS distinguishes between connections and sessions.  A new
    handshake creates both a connection and a session.  Data is
    transmitted over the connection.

    The session contains a more permanent record of the handshake.  The
    session can be inspected to determine handshake results.  The
    session can also be used to create a new connection through
    "session resumption". If the client and server both support this,
    they can create a new connection based on an old session without
    the overhead of a full handshake.

    The session for a :py:class:`~tlslite.tlsconnection.TLSConnection` can be
    retrieved from the connection's 'session' attribute.

    :vartype srpUsername: str
    :ivar srpUsername: The client's SRP username (or None).

    :vartype clientCertChain: ~tlslite.x509certchain.X509CertChain
    :ivar clientCertChain: The client's certificate chain (or None).

    :vartype serverCertChain: ~tlslite.x509certchain.X509CertChain
    :ivar serverCertChain: The server's certificate chain (or None).

    :vartype tackExt: tack.structures.TackExtension.TackExtension
    :ivar tackExt: The server's TackExtension (or None).

    :vartype tackInHelloExt: bool
    :ivar tackInHelloExt: True if a TACK was presented via TLS Extension.

    :vartype ~.encryptThenMAC: bool
    :ivar ~.encryptThenMAC: True if connection uses CBC cipher in
        encrypt-then-MAC mode

    :vartype appProto: bytearray
    :ivar appProto: name of the negotiated application level protocol, None
        if not negotiated

    :vartype cl_app_secret: bytearray
    :ivar cl_app_secret: key used for deriving keys used by client to encrypt
        and protect data in TLS 1.3

    :vartype sr_app_secret: bytearray
    :ivar sr_app_secret: key used for deriving keys used by server to encrypt
        and protect data in TLS 1.3

    :vartype exporterMasterSecret: bytearray
    :ivar exporterMasterSecret: master secret used for TLS Exporter in TLS1.3

    :vartype resumptionMasterSecret: bytearray
    :ivar resumptionMasterSecret: master secret used for session resumption in
        TLS 1.3

    :vartype tickets: list
    :ivar tickets: list of TLS 1.3 session tickets received from the server

    :vartype tls_1_0_tickets: list
    :ivar tls_1_0_tickets: list of TLS 1.2 and earlier session tickets received
        from the server
    """

    def __init__(self):
        self.masterSecret = bytearray(0)
        self.sessionID = bytearray(0)
        self.cipherSuite = 0
        self.srpUsername = ''
        self.clientCertChain = None
        self.serverCertChain = None
        self.tackExt = None
        self.tackInHelloExt = False
        self.serverName = ''
        self.resumable = False
        self.encryptThenMAC = False
        self.extendedMasterSecret = False
        self.appProto = bytearray(0)
        self.cl_app_secret = bytearray(0)
        self.sr_app_secret = bytearray(0)
        self.exporterMasterSecret = bytearray(0)
        self.resumptionMasterSecret = bytearray(0)
        self.tickets = None
        self.tls_1_0_tickets = None

    def valid(self):
        """If this session can be used for session resumption.

        :rtype: bool
        :returns: If this session can be used for session resumption.
        """
        pass

    def getCipherName(self):
        """Get the name of the cipher used with this connection.

        :rtype: str
        :returns: The name of the cipher used with this connection.
        """
        pass

    def getMacName(self):
        """Get the name of the HMAC hash algo used with this connection.

        :rtype: str
        :returns: The name of the HMAC hash algo used with this connection.
        """
        pass


class Ticket(object):
    """
    This class holds the ticket and ticket lifetime which are recieved from
    the server, together with the session object, it's all the information
    needed to resume a session using SessionTickets in TLSv1.2.
    Currently objects of this class are only used in client side session cache
    where we can iterate over them and use them for resumption when possible.

    :vartype ticket: bytearray
    :ivar ticket: the actual ticket recieved from the server

    :vartype ticket_lifetime: int
    :ivar ticket_lifetime: lifetime of the ticket defined by the server

    :vartype master_secret: bytearray
    :ivar master_secret: master secret used to resume the session

    :vartype cipher_suite: int
    :ivar cipher_suite: ciphersuite used to resume the session

    :vartype time_recieved: int
    :ivar time_recieved: the actual time when we recieved the ticket
    """

    def __init__(self, ticket, ticket_lifetime, master_secret, cipher_suite):
        self.ticket = ticket
        self.ticket_lifetime = ticket_lifetime
        self.master_secret = master_secret
        self.cipher_suite = cipher_suite
        self.time_received = time.time()
