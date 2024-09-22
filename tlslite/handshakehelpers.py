"""Class with various handshake helpers."""
from .extensions import PaddingExtension, PreSharedKeyExtension
from .utils.cryptomath import derive_secret, secureHMAC, HKDF_expand_label
from .utils.constanttime import ct_compare_digest
from .errors import TLSIllegalParameterException


class HandshakeHelpers(object):
    """
    This class encapsulates helper functions to be used with a TLS handshake.
    """

    @staticmethod
    def alignClientHelloPadding(clientHello):
        """
        Align ClientHello using the Padding extension to 512 bytes at least.

        :param ClientHello clientHello: ClientHello to be aligned
        """
        pass

    @staticmethod
    def _calc_binder(prf, psk, handshake_hash, external=True):
        """
        Calculate the binder value for a given HandshakeHash (that includes
        a truncated client hello already)
        """
        pass

    @staticmethod
    def calc_res_binder_psk(iden, res_master_secret, tickets):
        """Calculate PSK associated with provided ticket identity."""
        pass

    @staticmethod
    def update_binders(client_hello, handshake_hashes, psk_configs, tickets
        =None, res_master_secret=None):
        """
        Sign the Client Hello using TLS 1.3 PSK binders.

        note: the psk_configs should be in the same order as the ones in the
        PreSharedKeyExtension extension (extra ones are ok)

        :param client_hello: ClientHello to sign
        :param handshake_hashes: hashes of messages exchanged so far
        :param psk_configs: PSK identities and secrets
        :param tickets: optional list of tickets received from server
        :param bytearray res_master_secret: secret associated with the
            tickets
        """
        pass

    @staticmethod
    def verify_binder(client_hello, handshake_hashes, position, secret, prf,
        external=True):
        """Verify the PSK binder value in client hello.

        :param client_hello: ClientHello to verify
        :param handshake_hashes: hashes of messages exchanged so far
        :param position: binder at which position should be verified
        :param secret: the secret PSK
        :param prf: name of the hash used as PRF
        """
        pass
