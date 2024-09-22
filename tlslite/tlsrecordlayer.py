"""Helper class for TLSConnection."""
from __future__ import generators
import io
import time
import socket
from .utils.compat import *
from .utils.cryptomath import *
from .utils.codec import Parser, BadCertificateError
from .utils.lists import to_str_delimiter, getFirstMatching
from .errors import *
from .messages import *
from .mathtls import *
from .constants import *
from .recordlayer import RecordLayer
from .defragmenter import Defragmenter
from .handshakehashes import HandshakeHashes
from .bufferedsocket import BufferedSocket
from .handshakesettings import HandshakeSettings
from .keyexchange import KeyExchange


class TLSRecordLayer(object):
    """
    This class handles data transmission for a TLS connection.

    Its only subclass is :py:class:`~tlslite.tlsconnection.TLSConnection`.
    We've
    separated the code in this class from TLSConnection to make things
    more readable.


    :vartype sock: socket.socket
    :ivar sock: The underlying socket object.

    :vartype session: ~tlslite.Session.Session
    :ivar session: The session corresponding to this connection.
        Due to TLS session resumption, multiple connections can correspond
        to the same underlying session.

    :vartype ~.version: tuple
    :ivar ~.version: The TLS version being used for this connection.
        (3,0) means SSL 3.0, and (3,1) means TLS 1.0.

    :vartype closed: bool
    :ivar closed: If this connection is closed.

    :vartype resumed: bool
    :ivar resumed: If this connection is based on a resumed session.

    :vartype allegedSrpUsername: str or None
    :ivar allegedSrpUsername:  This is set to the SRP username
        asserted by the client, whether the handshake succeeded or not.
        If the handshake fails, this can be inspected to determine
        if a guessing attack is in progress against a particular user
        account.

    :vartype closeSocket: bool
    :ivar closeSocket: If the socket should be closed when the
        connection is closed, defaults to True (writable).

        If you set this to True, TLS Lite will assume the responsibility of
        closing the socket when the TLS Connection is shutdown (either
        through an error or through the user calling close()).  The default
        is False.

    :vartype ignoreAbruptClose: bool
    :ivar ignoreAbruptClose: If an abrupt close of the socket should
        raise an error (writable).

        If you set this to True, TLS Lite will not raise a
        :py:class:`~tlslite.errors.TLSAbruptCloseError` exception if the
        underlying
        socket is unexpectedly closed.  Such an unexpected closure could be
        caused by an attacker.  However, it also occurs with some incorrect
        TLS implementations.

        You should set this to True only if you're not worried about an
        attacker truncating the connection, and only if necessary to avoid
        spurious errors.  The default is False.

    :vartype ~.encryptThenMAC: bool
    :ivar ~.encryptThenMAC: Whether the connection uses the encrypt-then-MAC
        construct for CBC cipher suites, will be False also if connection uses
        RC4 or AEAD.

    :vartype recordSize: int
    :ivar recordSize: maximum size of data to be sent in a single record layer
        message. Note that after encryption is established (generally after
        handshake protocol has finished) the actual amount of data written to
        network socket will be larger because of the record layer header,
        padding
        or encryption overhead. It can be set to low value (so that there is no
        fragmentation on Ethernet, IP and TCP level) at the beginning of
        connection to reduce latency and set to protocol max (2**14) to
        maximise
        throughput after sending the first few kiB of data. If negotiated,
        record_size_limit extension may limit it though, causing reading of the
        variable to return lower value that was initially set.
        See also: HandshakeSettings.record_size_limit.

    :vartype tickets: list of bytearray
    :ivar tickets: list of session tickets received from server, oldest first.

    :vartype client_cert_required: bool
    :ivar client_cert_required: Set to True to make the post-handshake
        authentication fail when client doesn't provide a certificate in
        response
    """

    def __init__(self, sock):
        sock = BufferedSocket(sock)
        self.sock = sock
        self._recordLayer = RecordLayer(sock)
        self.session = None
        self._defragmenter = Defragmenter()
        self._defragmenter.add_static_size(ContentType.change_cipher_spec, 1)
        self._defragmenter.add_static_size(ContentType.alert, 2)
        self._defragmenter.add_dynamic_size(ContentType.handshake, 1, 3)
        self.clearReadBuffer()
        self.clearWriteBuffer()
        self._handshake_hash = HandshakeHashes()
        self._certificate_verify_handshake_hash = None
        self._pre_client_hello_handshake_hash = None
        self.closed = True
        self._refCount = 0
        self.resumed = False
        self.allegedSrpUsername = None
        self.closeSocket = True
        self.ignoreAbruptClose = False
        self.fault = None
        self._user_record_limit = 16384
        self.tickets = []
        self.tls_1_0_tickets = []
        self.heartbeat_can_receive = False
        self.heartbeat_can_send = False
        self.heartbeat_supported = False
        self.heartbeat_response_callback = None
        self._buffer_content_type = None
        self._buffer = bytearray()
        self._client_keypair = None
        self._cert_requests = {}
        self.client_cert_required = False
        self._middlebox_compat_mode = True

    @property
    def _send_record_limit(self):
        """Maximum size of payload that can be sent."""
        pass

    @_send_record_limit.setter
    def _send_record_limit(self, value):
        """Maximum size of payload that can be sent."""
        pass

    @property
    def _recv_record_limit(self):
        """Maximum size of payload that can be received."""
        pass

    @_recv_record_limit.setter
    def _recv_record_limit(self, value):
        """Maximum size of payload that can be received."""
        pass

    @property
    def recordSize(self):
        """Maximum size of the records that will be sent out."""
        pass

    @recordSize.setter
    def recordSize(self, value):
        """Size to automatically fragment records to."""
        pass

    @property
    def _client(self):
        """Boolean stating if the endpoint acts as a client"""
        pass

    @_client.setter
    def _client(self, value):
        """Set the endpoint to act as a client or not"""
        pass

    @property
    def version(self):
        """Get the SSL protocol version of connection"""
        pass

    @version.setter
    def version(self, value):
        """
        Set the SSL protocol version of connection

        The setter is a public method only for backwards compatibility.
        Don't use it! See at HandshakeSettings for options to set desired
        protocol version.
        """
        pass

    @property
    def encryptThenMAC(self):
        """Whether the connection uses Encrypt Then MAC (RFC 7366)"""
        pass

    def read(self, max=None, min=1):
        """Read some data from the TLS connection.

        This function will block until at least 'min' bytes are
        available (or the connection is closed).

        If an exception is raised, the connection will have been
        automatically closed.

        :type max: int
        :param max: The maximum number of bytes to return.

        :type min: int
        :param min: The minimum number of bytes to return

        :rtype: str
        :returns: A string of no more than 'max' bytes, and no fewer
            than 'min' (unless the connection has been closed, in which
            case fewer than 'min' bytes may be returned).

        :raises socket.error: If a socket error occurs.
        :raises tlslite.errors.TLSAbruptCloseError: If the socket is closed
            without a preceding alert.
        :raises tlslite.errors.TLSAlert: If a TLS alert is signalled.
        """
        pass

    def readAsync(self, max=None, min=1):
        """Start a read operation on the TLS connection.

        This function returns a generator which behaves similarly to
        read().  Successive invocations of the generator will return 0
        if it is waiting to read from the socket, 1 if it is waiting
        to write to the socket, or a string if the read operation has
        completed.

        :rtype: iterable
        :returns: A generator; see above for details.
        """
        pass

    def unread(self, b):
        """Add bytes to the front of the socket read buffer for future
        reading. Be careful using this in the context of select(...): if you
        unread the last data from a socket, that won't wake up selected waiters,
        and those waiters may hang forever.
        """
        pass

    def write(self, s):
        """Write some data to the TLS connection.

        This function will block until all the data has been sent.

        If an exception is raised, the connection will have been
        automatically closed.

        :type s: str
        :param s: The data to transmit to the other party.

        :raises socket.error: If a socket error occurs.
        """
        pass

    def writeAsync(self, s):
        """Start a write operation on the TLS connection.

        This function returns a generator which behaves similarly to
        write().  Successive invocations of the generator will return
        1 if it is waiting to write to the socket, or will raise
        StopIteration if the write operation has completed.

        :rtype: iterable
        :returns: A generator; see above for details.
        """
        pass

    def close(self):
        """Close the TLS connection.

        This function will block until it has exchanged close_notify
        alerts with the other party.  After doing so, it will shut down the
        TLS connection.  Further attempts to read through this connection
        will return "".  Further attempts to write through this connection
        will raise ValueError.

        If makefile() has been called on this connection, the connection
        will be not be closed until the connection object and all file
        objects have been closed.

        Even if an exception is raised, the connection will have been
        closed.

        :raises socket.error: If a socket error occurs.
        :raises tlslite.errors.TLSAbruptCloseError: If the socket is closed
            without a preceding alert.
        :raises tlslite.errors.TLSAlert: If a TLS alert is signalled.
        """
        pass
    _decref_socketios = close

    def closeAsync(self):
        """Start a close operation on the TLS connection.

        This function returns a generator which behaves similarly to
        close().  Successive invocations of the generator will return 0
        if it is waiting to read from the socket, 1 if it is waiting
        to write to the socket, or will raise StopIteration if the
        close operation has completed.

        :rtype: iterable
        :returns: A generator; see above for details.
        """
        pass

    def getVersionName(self):
        """Get the name of this TLS version.

        :rtype: str
        :returns: The name of the TLS version used with this connection.
            Either None, 'SSL 3.0', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2' or
            'TLS 1.3'.
        """
        pass

    def getCipherName(self):
        """Get the name of the cipher used with this connection.

        :rtype: str
        :returns: The name of the cipher used with this connection.
            Either 'aes128', 'aes256', 'rc4', or '3des'.
        """
        pass

    def getCipherImplementation(self):
        """Get the name of the cipher implementation used with
        this connection.

        :rtype: str
        :returns: The name of the cipher implementation used with
            this connection.  Either 'python', 'openssl', or 'pycrypto'.
        """
        pass

    def send(self, s):
        """Send data to the TLS connection (socket emulation).

        :raises socket.error: If a socket error occurs.
        """
        pass

    def sendall(self, s):
        """Send data to the TLS connection (socket emulation).

        :raises socket.error: If a socket error occurs.
        """
        pass

    def recv(self, bufsize):
        """Get some data from the TLS connection (socket emulation).

        :raises socket.error: If a socket error occurs.
        :raises tlslite.errors.TLSAbruptCloseError: If the socket is closed
            without a preceding alert.
        :raises tlslite.errors.TLSAlert: If a TLS alert is signalled.
        """
        pass

    def makefile(self, mode='r', bufsize=-1):
        """Create a file object for the TLS connection (socket emulation).

        :rtype: socket._fileobject
        """
        pass

    def getsockname(self):
        """Return the socket's own address (socket emulation)."""
        pass

    def getpeername(self):
        """Return the remote address to which the socket is connected
        (socket emulation)."""
        pass

    def settimeout(self, value):
        """Set a timeout on blocking socket operations (socket emulation)."""
        pass

    def gettimeout(self):
        """Return the timeout associated with socket operations (socket
        emulation)."""
        pass

    def setsockopt(self, level, optname, value):
        """Set the value of the given socket option (socket emulation)."""
        pass

    def shutdown(self, how):
        """Shutdown the underlying socket."""
        pass

    def fileno(self):
        """Not implement in TLS Lite."""
        pass

    def _handle_srv_pha(self, cert):
        """Process the post-handshake authentication from client."""
        pass

    def _sendMsg(self, msg, randomizeFirstBlock=True, update_hashes=True):
        """Fragment and send message through socket"""
        pass

    def _queue_message(self, msg):
        """Just queue message for sending, for record layer coalescing."""
        pass

    def _queue_flush(self):
        """Send the queued messages."""
        pass

    def _sendMsgThroughSocket(self, msg):
        """Send message, handle errors"""
        pass

    def _getNextRecord(self):
        """read next message from socket, defragment message"""
        pass

    def _getNextRecordFromSocket(self):
        """Read a record, handle errors"""
        pass

    def write_heartbeat(self, payload, padding_length):
        """Start a write operation of heartbeat_request.

        :type payload: bytes
        :param payload: Payload, that we want send in request and
                        get at response.

        :type padding_length: int
        :param padding_length: Length of padding.

        :raise socket.error: If a socket error occurs.
        """
        pass

    def send_heartbeat_request(self, payload, padding_length):
        """Synchronous version of write_heartbeat function.

        :type payload: bytes
        :param payload: Payload, that we want send in request and
             get at response.

        :type padding_length: int
        :param padding_length: Length of padding.

        :raise socket.error: If a socket error occurs.
        """
        pass

    def _handle_keyupdate_request(self, request):
        """Process the KeyUpdate request.

        :type request: KeyUpdate
        :param request: Recieved KeyUpdate message.
        """
        pass

    def send_keyupdate_request(self, message_type):
        """Send a KeyUpdate message.

        :type payload: int
        :param payload: Type of KeyUpdate message.

        :raise socket.error: If a socket error occurs.
        """
        pass
