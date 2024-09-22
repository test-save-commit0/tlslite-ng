"""xmlrpcserver.py - simple XML RPC server supporting TLS."""
try:
    from SimpleXMLRPCServer import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler
except ImportError:
    from xmlrpc.server import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler
from .tlssocketservermixin import TLSSocketServerMixIn


class TLSXMLRPCRequestHandler(SimpleXMLRPCRequestHandler):
    """XMLRPCRequestHandler using TLS."""

    def setup(self):
        """Setup the connection for TLS."""
        pass

    def do_POST(self):
        """Handle the HTTPS POST request."""
        pass


class TLSXMLRPCServer(TLSSocketServerMixIn, SimpleXMLRPCServer):
    """Simple XML-RPC server using TLS."""

    def __init__(self, addr, *args, **kwargs):
        if not args and not 'requestHandler' in kwargs:
            kwargs['requestHandler'] = TLSXMLRPCRequestHandler
        SimpleXMLRPCServer.__init__(self, addr, *args, **kwargs)


class MultiPathTLSXMLRPCServer(TLSXMLRPCServer):
    """Multipath XML-RPC Server using TLS."""

    def __init__(self, addr, *args, **kwargs):
        TLSXMLRPCServer.__init__(addr, *args, **kwargs)
        self.dispatchers = {}
        self.allow_none = allow_none
        self.encoding = encoding
