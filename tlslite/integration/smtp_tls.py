"""TLS Lite + smtplib."""
from smtplib import SMTP
from tlslite.tlsconnection import TLSConnection
from tlslite.integration.clienthelper import ClientHelper


class SMTP_TLS(SMTP):
    """This class extends :py:class:`smtplib.SMTP` with TLS support."""

    def starttls(self, username=None, password=None, certChain=None,
        privateKey=None, checker=None, settings=None):
        """Puts the connection to the SMTP server into TLS mode.

        If the server supports TLS, this will encrypt the rest of the SMTP
        session.

        For client authentication, use one of these argument
        combinations:

         - username, password (SRP)
         - certChain, privateKey (certificate)

        For server authentication, you can either rely on the
        implicit mutual authentication performed by SRP or
        you can do certificate-based server
        authentication with one of these argument combinations:

         - x509Fingerprint

        Certificate-based server authentication is compatible with
        SRP or certificate-based client authentication.

        The caller should be prepared to handle TLS-specific
        exceptions.  See the client handshake functions in
        :py:class:`~tlslite.tlsconnection.TLSConnection` for details on which
        exceptions might be raised.

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
        """
        # First, send the STARTTLS command to the SMTP server
        (code, resp) = self.docmd("STARTTLS")
        if code != 220:
            raise SMTPException("STARTTLS extension not supported by server.")

        # Create a TLSConnection instance
        tlsConnection = TLSConnection(self.sock)

        # Set up the ClientHelper
        helper = ClientHelper(username, password, certChain, privateKey, checker, settings)

        # Perform the TLS handshake
        try:
            helper.handshakeClientCert(tlsConnection)
        except Exception as e:
            raise SMTPException(f"TLS handshake failed: {str(e)}")

        # Replace the original socket with the TLS connection
        self.sock = tlsConnection
        self.file = tlsConnection.makefile('rb')

        # Re-initialize the SMTP connection
        (code, msg) = self.ehlo()
        if code != 250:
            raise SMTPException("EHLO failed after STARTTLS")

        return (code, msg)
