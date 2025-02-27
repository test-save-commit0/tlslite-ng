"""TLS Lite + SocketServer."""
from tlslite.tlsconnection import TLSConnection


class TLSSocketServerMixIn:
    """
    This class can be mixed in with any :py:class:`SocketServer.TCPServer` to
    add TLS support.

    To use this class, define a new class that inherits from it and
    some :py:class:`SocketServer.TCPServer` (with the mix-in first). Then
    implement the :py:meth:`handshake` method, doing some sort of server
    handshake on the connection argument.  If the handshake method
    returns True, the RequestHandler will be triggered.  Below is a
    complete example of a threaded HTTPS server::

        from SocketServer import *
        from BaseHTTPServer import *
        from SimpleHTTPServer import *
        from tlslite import *

        s = open("./serverX509Cert.pem").read()
        x509 = X509()
        x509.parse(s)
        cert_chain = X509CertChain([x509])

        s = open("./serverX509Key.pem").read()
        privateKey = parsePEMKey(s, private=True)

        sessionCache = SessionCache()

        class MyHTTPServer(ThreadingMixIn, TLSSocketServerMixIn,
                           HTTPServer):
          def handshake(self, tlsConnection):
              try:
                  tlsConnection.handshakeServer(certChain=cert_chain,
                                                privateKey=privateKey,
                                                sessionCache=sessionCache)
                  tlsConnection.ignoreAbruptClose = True
                  return True
              except TLSError, error:
                  print "Handshake failure:", str(error)
                  return False

        httpd = MyHTTPServer(('localhost', 443), SimpleHTTPRequestHandler)
        httpd.serve_forever()
    """
