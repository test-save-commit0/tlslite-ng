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
        current_length = len(clientHello.write())
        target_length = ((current_length + 511) // 512) * 512
        padding_length = target_length - current_length

        padding_extension = next((ext for ext in clientHello.extensions
                                  if isinstance(ext, PaddingExtension)), None)
        
        if padding_extension:
            padding_extension.paddingData = bytearray(padding_length)
        else:
            clientHello.extensions.append(PaddingExtension().create(padding_length))

    @staticmethod
    def _calc_binder(prf, psk, handshake_hash, external=True):
        """
        Calculate the binder value for a given HandshakeHash (that includes
        a truncated client hello already)
        """
        if external:
            label = b"ext binder"
        else:
            label = b"res binder"

        early_secret = secureHMAC(bytearray(len(prf.digest())), psk, prf)
        binder_key = derive_secret(early_secret, label, None, prf)
        return secureHMAC(binder_key, handshake_hash.digest(prf), prf)

    @staticmethod
    def calc_res_binder_psk(iden, res_master_secret, tickets):
        """Calculate PSK associated with provided ticket identity."""
        for ticket in tickets:
            if ticket.ticket == iden:
                prf = ticket.prf
                hash_name = prf.name
                nonce = ticket.ticket_nonce
                return HKDF_expand_label(res_master_secret, b"resumption",
                                         nonce, prf.digest_size, prf)
        raise TLSIllegalParameterException("Ticket not found")

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
        psk_ext = next((ext for ext in client_hello.extensions
                        if isinstance(ext, PreSharedKeyExtension)), None)
        if not psk_ext:
            return

        binders = []
        for i, (identity, psk) in enumerate(psk_configs):
            if isinstance(psk, bytearray):
                external = True
            else:
                external = False
                psk = HandshakeHelpers.calc_res_binder_psk(identity, res_master_secret, tickets)

            binder = HandshakeHelpers._calc_binder(psk_ext.prf, psk,
                                                   handshake_hashes.copy(),
                                                   external)
            binders.append(binder)

        psk_ext.binders = binders

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
        psk_ext = next((ext for ext in client_hello.extensions
                        if isinstance(ext, PreSharedKeyExtension)), None)
        if not psk_ext:
            raise TLSIllegalParameterException("No PSK extension")

        if position >= len(psk_ext.binders):
            raise TLSIllegalParameterException("Invalid binder position")

        binder = psk_ext.binders[position]
        calculated_binder = HandshakeHelpers._calc_binder(prf, secret,
                                                          handshake_hashes.copy(),
                                                          external)

        if not ct_compare_digest(binder, calculated_binder):
            raise TLSIllegalParameterException("Binder does not verify")
