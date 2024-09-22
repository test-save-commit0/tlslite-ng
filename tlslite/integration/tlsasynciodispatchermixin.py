"""TLS Lite + asyncio."""
import asyncio
from tlslite.tlsconnection import TLSConnection
from .asyncstatemachine import AsyncStateMachine


class TLSAsyncioDispatcherMixIn(asyncio.Protocol):
    """
        This class can be "mixed in" with an :py:class:`asyncio.Protocol`
        to add TLS support.

        This class essentially sits between the protocol and the asyncio
        event loop, intercepting events and only
        calling the protocol when applicable.

        In the case of :py:meth:`data_received`, a read operation will be
        activated, and when it completes, the bytes will be placed in a
        buffer where the protocol can retrieve them by calling :py:meth:`recv`,
        and the protocol's :py:meth:`data_received` will be called.

        In the case of :py:meth:`send`, the protocol's :py:meth:`send` will
        be called, and when it calls :py:meth:`send`, a write operation
        will be activated.

        To use this class, you must combine it with an asyncio.Protocol, and
        pass in a handshake operation with setServerHandshakeOp().

        Below is an example of using this class with aiohttp. This class
        is mixed in with aiohttp's BaseProtocol to create http_tls_protocol.

        Note:

        1. the mix-in is listed first in the inheritance list

        2. the input buffer size must be at least 16K, otherwise the protocol
        might not read all the bytes from the TLS layer, leaving some
        bytes in limbo.

        3. IE seems to have a problem receiving a whole HTTP response
        in a single TLS record, so HTML pages containing
        '\\r\\n\\r\\n' won't be displayed on IE.

        Add the following text into 'start_aiohttp.py', in the
        'HTTP Server' section::

            from tlslite import *
            s = open("./serverX509Cert.pem").read()
            x509 = X509()
            x509.parse(s)
            cert_chain = X509CertChain([x509])

            s = open("./serverX509Key.pem").read()
            privateKey = parsePEMKey(s, private=True)

            class http_tls_protocol(TLSAsyncioProtocol,
                                    aiohttp.BaseProtocol):
                ac_in_buffer_size = 16384

                def __init__ (self, server, conn, addr):
                    aiohttp.BaseProtocol.__init__(self, server, conn, addr)
                    TLSAsyncioProtocol.__init__(self, conn)
                    self.tls_connection.ignoreAbruptClose = True
                    self.setServerHandshakeOp(certChain=cert_chain,
                                              privateKey=privateKey)

            hs.protocol_class = http_tls_protocol

        If the TLS layer raises an exception, the exception will be caught in
        asyncio.Protocol, which will call :py:meth:`close` on this class.
        The TLS layer always closes the TLS connection before raising an
        exception, so the close operation will complete right away, causing
        asyncio.Protocol.close() to be called, which closes the socket and
        removes this instance from the asyncio event loop.
    """

    def __init__(self, sock=None):
        """Initialize the protocol with the given socket."""
        super().__init__()
        if sock:
            self.tls_connection = TLSConnection(sock)
        self.sibling_class = self._get_sibling_class()

    def _get_sibling_class(self):
        """Get the sibling class that this class is mixed in with."""
        pass

    def readable(self):
        """Check if the protocol is ready for reading."""
        pass

    def writable(self):
        """Check if the protocol is ready for writing."""
        pass

    def handle_read(self):
        """Handle a read event."""
        pass

    def handle_write(self):
        """Handle a write event."""
        pass

    def out_connect_event(self):
        """Handle an outgoing connect event."""
        pass

    def out_close_event(self):
        """Handle an outgoing close event."""
        pass

    def out_read_event(self, read_buffer):
        """Handle an outgoing read event."""
        pass

    def out_write_event(self):
        """Handle an outgoing write event."""
        pass

    def recv(self, buffer_size=16384):
        """Receive data."""
        pass

    def close(self):
        """Close the connection."""
        pass
