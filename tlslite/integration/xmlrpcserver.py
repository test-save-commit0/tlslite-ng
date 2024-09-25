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
        self.connection = self.request
        self.rfile = self.connection.makefile('rb', self.rbufsize)
        self.wfile = self.connection.makefile('wb', self.wbufsize)

    def do_POST(self):
        """Handle the HTTPS POST request."""
        try:
            # Get the request data
            content_len = int(self.headers.get('content-length', 0))
            post_body = self.rfile.read(content_len)
            
            # Process the request
            response = self.server._marshaled_dispatch(
                post_body, getattr(self, '_dispatch', None), self.path
            )
            
            # Send response
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.send_header("Content-length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)
            self.wfile.flush()
        except Exception:  # This is the same behavior as in SimpleXMLRPCRequestHandler
            self.send_response(500)
            self.end_headers()


class TLSXMLRPCServer(TLSSocketServerMixIn, SimpleXMLRPCServer):
    """Simple XML-RPC server using TLS."""

    def __init__(self, addr, *args, **kwargs):
        if not args and not 'requestHandler' in kwargs:
            kwargs['requestHandler'] = TLSXMLRPCRequestHandler
        SimpleXMLRPCServer.__init__(self, addr, *args, **kwargs)


class MultiPathTLSXMLRPCServer(TLSXMLRPCServer):
    """Multipath XML-RPC Server using TLS."""

    def __init__(self, addr, *args, **kwargs):
        TLSXMLRPCServer.__init__(self, addr, *args, **kwargs)
        self.dispatchers = {}
        self.allow_none = kwargs.get('allow_none', False)
        self.encoding = kwargs.get('encoding', 'utf-8')

    def add_dispatcher(self, path, dispatcher):
        self.dispatchers[path] = dispatcher

    def get_dispatcher(self, path):
        return self.dispatchers.get(path, self.instance)

    def _marshaled_dispatch(self, data, dispatch_method=None, path=None):
        try:
            params, method = xmlrpclib.loads(data)

            # Get the appropriate dispatcher based on the path
            dispatcher = self.get_dispatcher(path)

            if dispatch_method is not None:
                response = dispatch_method(dispatcher, method, params)
            else:
                response = self._dispatch(dispatcher, method, params)

            # Convert the response to XML-RPC format
            response = (response,)
            response = xmlrpclib.dumps(response, methodresponse=1,
                                       allow_none=self.allow_none, encoding=self.encoding)
        except Fault as fault:
            response = xmlrpclib.dumps(fault, allow_none=self.allow_none,
                                       encoding=self.encoding)
        except:
            # Report exception back to server
            response = xmlrpclib.dumps(
                xmlrpclib.Fault(1, "%s:%s" % (sys.exc_info()[0], sys.exc_info()[1])),
                encoding=self.encoding, allow_none=self.allow_none,
            )

        return response.encode(self.encoding)

    def _dispatch(self, dispatcher, method, params):
        try:
            # Check if the requested method is available in the dispatcher
            func = getattr(dispatcher, 'dispatch')
            if callable(func):
                return func(method, params)
            else:
                raise Exception('method "%s" is not supported' % method)
        except Exception as e:
            raise xmlrpclib.Fault(1, str(e))
