""" Helper package for handling TLS extensions encountered in ClientHello
and ServerHello messages.
"""
from __future__ import generators
from collections import namedtuple
from .utils.codec import Writer, Parser, DecodeError
from .constants import NameType, ExtensionType, CertificateStatusType, SignatureAlgorithm, HashAlgorithm, SignatureScheme, PskKeyExchangeMode, CertificateType, GroupName, ECPointFormat, HeartbeatMode
from .errors import TLSInternalError


class TLSExtension(object):
    """
    Base class for handling handshake protocol hello messages extensions.

    This class handles the generic information about TLS extensions used by
    both sides of connection in Client Hello and Server Hello messages.
    See https://tools.ietf.org/html/rfc4366 for more info.

    It is used as a base class for specific users and as a way to store
    extensions that are not implemented in library.

    To implement a new extension you will need to create a new class which
    calls this class contructor (__init__), usually specifying just the
    extType parameter. The other methods which need to be implemented are:
    `extData`, `create`, `parse` and `__repr__`. If the parser can be used
    for client and optionally server extensions, the extension constructor
    should be added to `_universalExtensions`. Otherwise, when the client and
    server extensions have completely different forms, you should add client
    form to the `_universalExtensions` and the server form to
    `_serverExtensions`. Since the server MUST NOT send extensions not
    advertised by client, there are no purely server-side extensions. But
    if the client side extension is just marked by presence and has no payload,
    the client side (thus the `_universalExtensions` may be skipped, then
    the `TLSExtension` class will be used for implementing it. See
    end of the file for type-to-constructor bindings.

    .. note:: Subclassing for the purpose of parsing extensions
        is not an officially supported part of API (just as underscores in
        their
        names would indicate).

    :vartype extType: int
    :ivar extType: a 2^16-1 limited integer specifying the type of the
        extension that it contains, e.g. 0 indicates server name extension

    :vartype ~.extData: bytearray
    :ivar ~.extData: a byte array containing the value of the extension as
        to be written on the wire

    :vartype serverType: boolean
    :ivar serverType: indicates that the extension was parsed with ServerHello
        specific parser, otherwise it used universal or ClientHello specific
        parser

    :vartype encExtType: boolean
    :ivar encExtType: indicates that the extension should be the type from
        Encrypted Extensions

    :vartype _universalExtensions: dict
    :cvar _universalExtensions: dictionary with concrete implementations of
        specific TLS extensions where key is the numeric value of the extension
        ID. Contains ClientHello version of extensions or universal
        implementations

    :vartype _serverExtensions: dict
    :cvar _serverExtensions: dictionary with concrete implementations of
        specific TLS extensions where key is the numeric value of the extension
        ID. Includes only those extensions that require special handlers for
        ServerHello versions.

    :vartype _certificateExtensions: dict
    :cvar _certificateExtensions: dictionary with concrete implementations of
        specific TLS extensions where the key is the numeric value of the
        type of the extension and the value is the class. Includes only
        those extensions that require special handlers for Certificate
        message.

    :vartype _hrrExtensions: dict
    :cvar _hrrExtensions: dictionary with concrete implementation of specific
        TLS extensions where the key is the numeric type of the extension
        and the value is the class. Includes only those extensions that require
        special handlers for the Hello Retry Request message.
    """
    _universalExtensions = {}
    _serverExtensions = {}
    _certificateExtensions = {}
    _hrrExtensions = {}

    def __init__(self, server=False, extType=None, encExt=False, cert=False,
        hrr=False):
        """
        Creates a generic TLS extension.

        You'll need to use :py:meth:`create` or :py:meth:`parse` methods to
        create an extension
        that is actually usable.

        :param bool server: whether to select ClientHello or ServerHello
            version
            for parsing
        :param int extType: type of extension encoded as an integer, to be used
            by subclasses
        :param bool encExt: whether to select the EncryptedExtensions type
            for parsing
        :param bool cert: whether to select the Certificate type
            of extension for parsing
        :param bool hrr: whether to select the Hello Retry Request type
            of extension for parsing
        """
        self.extType = extType
        self._extData = bytearray(0)
        self.serverType = server
        self.encExtType = encExt
        self.cert = cert
        self.hrr = hrr

    @property
    def extData(self):
        """
        Return the on the wire encoding of extension

        Child classes need to override this property so that it returns just
        the payload of an extension, that is, without the 4 byte generic header
        common to all extension. In other words, without the extension ID and
        overall extension length.

        :rtype: bytearray
        """
        pass

    def _oldCreate(self, extType, data):
        """Legacy handling of create method"""
        pass

    def _newCreate(self, data):
        """New format for create method"""
        pass

    def create(self, *args, **kwargs):
        """
        Initializes a generic TLS extension.

        The extension can carry arbitrary data and have arbitrary payload, can
        be used in client hello or server hello messages.

        The legacy calling method uses two arguments - the `extType` and
        `data`.
        If the new calling method is used, only one argument is passed in -
        `data`.

        Child classes need to override this method so that it is possible
        to set values for all fields used by the extension.

        :param int extType: if int: type of the extension encoded as an integer
            between `0` and `2^16-1`
        :param bytearray data: raw data representing extension on the wire
        :rtype: TLSExtension
        """
        pass

    def write(self):
        """Returns encoded extension, as encoded on the wire

        Note that child classes in general don't need to override this method.

        :rtype: bytearray
        :returns: An array of bytes formatted as is supposed to be written on
           the wire, including the extension_type, length and the extension
           data

        :raises AssertionError: when the object was not initialized
        """
        pass

    @staticmethod
    def _parseExt(parser, extType, extLength, extList):
        """Parse a extension using a predefined constructor"""
        pass

    def parse(self, p):
        """Parses extension from on the wire format

        Child classes should override this method so that it parses the
        extension from on the wire data. Note that child class parsers will
        not receive the generic header of the extension, but just a parser
        with the payload. In other words, the method should be the exact
        reverse of the `extData` property.

        :param tlslite.util.codec.Parser p:  data to be parsed

        :raises DecodeError: when the size of the passed element doesn't match
            the internal representation

        :rtype: TLSExtension
        """
        pass

    def __eq__(self, that):
        """Test if two TLS extensions are effectively the same

        Will check if encoding them will result in the same on the wire
        representation.

        Will return False for every object that's not an extension.
        """
        if hasattr(that, 'extType') and hasattr(that, 'extData'):
            return (self.extType == that.extType and self.extData == that.
                extData)
        return False

    def __repr__(self):
        """Output human readable representation of object

        Child classes should override this method to support more appropriate
        string rendering of the extension.

        :rtype: str
        """
        return (
            'TLSExtension(extType={0!r}, extData={1!r}, serverType={2!r}, encExtType={3!r})'
            .format(self.extType, self.extData, self.serverType, self.
            encExtType))


class CustomNameExtension(TLSExtension):
    """
    Abstract class for handling custom name for payload variable.

    Used for handling arbitrary extensions that deal with a single value
    in payload (either an opaque data, single value or single array).

    Must be subclassed.
    """

    def __init__(self, field_name, extType):
        """
        Create instance of the class.

        :param str field_name: name of the field to store the extension payload
        :param int ext_type: numerical ID of the extension
        """
        super(CustomNameExtension, self).__init__(extType=extType)
        self._field_name = field_name
        self._internal_value = None

    @property
    def extData(self):
        """
        Return raw data encoding of the extension.

        :rtype: bytearray
        """
        pass

    def create(self, values):
        """
        Set the list to specified values.

        :param list values: list of values to save
        """
        pass

    def parse(self, parser):
        """
        Deserialise extension from on-the-wire data.

        :param tlslite.utils.codec.Parser parser: data
        :rtype: Extension
        """
        pass

    def __getattr__(self, name):
        """Return the special field name value."""
        if name == '_field_name':
            raise AttributeError("type object '{0}' has no attribute '{1}'"
                .format(self.__class__.__name__, name))
        if name == self._field_name:
            return self._internal_value
        raise AttributeError("type object '{0}' has no attribute '{1}'".
            format(self.__class__.__name__, name))

    def __setattr__(self, name, value):
        """Set the special field value."""
        if hasattr(self, '_field_name') and name == self._field_name:
            self._internal_value = value
            return
        super(CustomNameExtension, self).__setattr__(name, value)


class VarBytesExtension(CustomNameExtension):
    """
    Abstract class for extension that deal with single byte array payload.

    Extension for handling arbitrary extensions that comprise of just
    a single bytearray of variable size.
    """

    def __init__(self, field_name, length_length, ext_type):
        """
        Crate instance of the class.

        :param str field_name: name of the field to store the bytearray
            that is the payload
        :param int length_length: number of bytes needed to encode the length
            field of the string
        :param int ext_type: numerical ID of the extension
        """
        super(VarBytesExtension, self).__init__(field_name, extType=ext_type)
        self._length_length = length_length

    @property
    def extData(self):
        """
        Return raw data encoding of the extension.

        :rtype: bytearray
        """
        pass

    def parse(self, parser):
        """Deserialise extension from on-the-wire data.

        :param tlslite.utils.codec.Parser parser: data
        :rtype: TLSExtension
        """
        pass

    def __repr__(self):
        """Return human readable representation of the extension."""
        if self._internal_value is not None:
            return '{0}(len({1})={2})'.format(self.__class__.__name__, self
                ._field_name, len(self._internal_value))
        return '{0}({1}=None)'.format(self.__class__.__name__, self._field_name
            )


class ListExtension(CustomNameExtension):
    """
    Abstract class for extensions that deal with single list in payload.

    Extension for handling arbitrary extensions comprising of just a list
    of same-sized elementes inside an array
    """

    def __init__(self, fieldName, extType, item_enum=None):
        """
        Create instance of the class.

        :param str fieldName: name of the field to store the list that is
            the payload
        :param int extType: numerical ID of the extension
        :param class item_enum: TLSEnum class that defines the enum of the
            items in the list
        """
        super(ListExtension, self).__init__(fieldName, extType=extType)
        self._item_enum = item_enum

    def _list_to_repr(self):
        """Return human redable representation of the item list"""
        pass

    def __repr__(self):
        """Return human readable representation of the extension."""
        return '{0}({1}={2})'.format(self.__class__.__name__, self.
            _field_name, self._list_to_repr())


class VarListExtension(ListExtension):
    """
    Abstract extension for handling extensions comprised of uniform value list.

    Extension for handling arbitrary extensions comprising of just a list
    of same-sized elementes inside an array
    """

    def __init__(self, elemLength, lengthLength, fieldName, extType,
        item_enum=None):
        """Create handler for extension that has a list of items as payload.

        :param int elemLength: number of bytes needed to encode single element
        :param int lengthLength: number of bytes needed to encode length field
        :param str fieldName: name of the field storing the list of elements
        :param int extType: numerical ID of the extension encoded
        :param class item_enum: TLSEnum class that defines entries in the list
        """
        super(VarListExtension, self).__init__(fieldName, extType=extType,
            item_enum=item_enum)
        self._elemLength = elemLength
        self._lengthLength = lengthLength

    @property
    def extData(self):
        """
        Return raw data encoding of the extension.

        :rtype: bytearray
        """
        pass

    def parse(self, parser):
        """
        Deserialise extension from on-the-wire data.

        :param tlslite.utils.codec.Parser parser: data
        :rtype: Extension
        """
        pass


class VarSeqListExtension(ListExtension):
    """
    Abstract extension for handling extensions comprised of tuple list.

    Extension for handling arbitrary extensions comprising of a single list
    of same-sized elements in same-sized tuples
    """

    def __init__(self, elemLength, elemNum, lengthLength, fieldName,
        extType, item_enum=None):
        """
        Create a handler for extension that has a list of tuples as payload.

        :param int elemLength: number of bytes needed to encode single element
            of a tuple
        :param int elemNum: number of elements in a tuple
        :param int lengthLength: number of bytes needed to encode overall
            length of the list
        :param str fieldName: name of the field storing the list of elements
        :param int extType: numerical ID of the extension encoded
        :param class item_enum: TLSEnum class that defines entries in the list
        """
        super(VarSeqListExtension, self).__init__(fieldName, extType=
            extType, item_enum=item_enum)
        self._elemLength = elemLength
        self._elemNum = elemNum
        self._lengthLength = lengthLength

    @property
    def extData(self):
        """
        Return raw data encoding of the extension.

        :rtype: bytearray
        """
        pass

    def parse(self, parser):
        """
        Deserialise extension from on-the-wire data.

        :param tlslite.utils.codec.Parser parser: data
        :rtype: Extension
        """
        pass


class IntExtension(CustomNameExtension):
    """
    Abstract class for extensions that deal with single integer in payload.

    Extension for handling arbitrary extensions that have a payload that is
    a single integer of a given size (1, 2, ... bytes)
    """

    def __init__(self, elem_length, field_name, ext_type, item_enum=None):
        """Create handler for extension that has a single integer as payload.

        :param str field_name: name of the field that will store the value
        :param int elem_length: size (in bytes) of the value in the extension
        :param int ext_tyoe: numerical ID of the extension encoded
        :param class item_enum: TLSEnum class that defines entries in the
            extension
        """
        super(IntExtension, self).__init__(field_name, extType=ext_type)
        self._elem_length = elem_length
        self._item_enum = item_enum

    def _entry_to_repr(self):
        """Return human readable representation of the value."""
        pass

    def __repr__(self):
        """Return human readable representation of the extension."""
        return '{0}({1}={2})'.format(self.__class__.__name__, self.
            _field_name, self._entry_to_repr())

    @property
    def extData(self):
        """Return raw data encoding of the extension.

        :rtype: bytearray
        """
        pass

    def parse(self, parser):
        """
        Deserialise extension from on-the-wire data.

        :param tlslite.utils.codec.Parser parser: data
        :rtype: Extension
        """
        pass


class SNIExtension(TLSExtension):
    """
    Class for handling Server Name Indication (server_name) extension from
    RFC 4366.

    Note that while usually the client does advertise just one name, it is
    possible to provide a list of names, each of different type.
    The type is a single byte value (represented by ints), the names are
    opaque byte strings, in case of DNS host names (records of type 0) they
    are UTF-8 encoded domain names (without the ending dot).

    :vartype hostNames: tuple of bytearrays
    :ivar hostNames: tuple of hostnames (server name records of type 0)
        advertised in the extension. Note that it may not include all names
        from client hello as the client can advertise other types. Also note
        that while it's not possible to change the returned array in place, it
        is possible to assign a new set of names. IOW, this won't work::

           sni_extension.hostNames[0] = bytearray(b'example.com')

        while this will work::

           names = list(sni_extension.hostNames)
           names[0] = bytearray(b'example.com')
           sni_extension.hostNames = names


    :vartype serverNames: list of :py:class:`ServerName`
    :ivar serverNames: list of all names advertised in extension.
        :py:class:`ServerName` is a namedtuple with two elements, the first
        element (type) defines the type of the name (encoded as int)
        while the other (name) is a bytearray that carries the value.
        Known types are defined in :py:class:`tlslite.constants.NameType`.
        The list will be empty if the on the wire extension had and empty
        list while it will be None if the extension was empty.

    :vartype extType: int
    :ivar extType: numeric type of SNIExtension, i.e. 0

    :vartype ~.extData: bytearray
    :ivar ~.extData: raw representation of the extension
    """
    ServerName = namedtuple('ServerName', 'name_type name')

    def __init__(self):
        """
        Create an instance of SNIExtension.

        See also: :py:meth:`create` and :py:meth:`parse`.
        """
        super(SNIExtension, self).__init__(extType=ExtensionType.server_name)
        self.serverNames = None

    def __repr__(self):
        """
        Return programmer-readable representation of extension

        :rtype: str
        """
        return 'SNIExtension(serverNames={0!r})'.format(self.serverNames)

    def create(self, hostname=None, hostNames=None, serverNames=None):
        """
        Initializes an instance with provided hostname, host names or
        raw server names.

        Any of the parameters may be `None`, in that case the list inside the
        extension won't be defined, if either `hostNames` or `serverNames` is
        an empty list, then the extension will define a list of length 0.

        If multiple parameters are specified at the same time, then the
        resulting list of names will be concatenated in order of hostname,
        hostNames and serverNames last.

        :param bytearray hostname: raw UTF-8 encoding of the host name

        :param list hostNames: list of raw UTF-8 encoded host names

        :param list serverNames: pairs of name_type and name encoded as a
            namedtuple

        :rtype: SNIExtension
        """
        pass

    @property
    def hostNames(self):
        """ Returns a simulated list of hostNames from the extension.

        :rtype: tuple of bytearrays
        """
        pass

    @hostNames.setter
    def hostNames(self, hostNames):
        """ Removes all host names from the extension and replaces them by
        names in `hostNames` parameter.

        Newly added parameters will be added at the beginning of the list
        of extensions.

        :param iterable hostNames: host names (bytearrays) to replace the
            old server names of type 0
        """
        pass

    @hostNames.deleter
    def hostNames(self):
        """
        Remove all host names from extension, leaves other name types
        unmodified.
        """
        pass

    @property
    def extData(self):
        """
        Raw encoding of extension data, without type and length header.

        :rtype: bytearray
        """
        pass

    def write(self):
        """
        Returns encoded extension, as encoded on the wire

        :rtype: bytearray
        :returns: an array of bytes formatted as they are supposed to be
            written
            on the wire, including the type, length and extension data
        """
        pass

    def parse(self, p):
        """
        Deserialise the extension from on-the-wire data

        The parser should not include the type or length of extension!

        :param tlslite.util.codec.Parser p: data to be parsed

        :rtype: SNIExtension
        :raises DecodeError: when the internal sizes don't match the attached
            data
        """
        pass


class SupportedVersionsExtension(VarSeqListExtension):
    """
    This class handles the SupportedVersion extensions used in TLS 1.3.

    See draft-ietf-tls-tls13.

    :vartype extType: int
    :ivar extType: numeric type of the Supported Versions extension, i.e. 43

    :vartype ~.extData: bytearray
    :ivar ~.extData: raw representation of the extension data

    :vartype versions: list of tuples
    :ivar versions: list of supported protocol versions; each tuple has two
        one byte long integers
    """

    def __init__(self):
        """Create an instance of SupportedVersionsExtension."""
        super(SupportedVersionsExtension, self).__init__(1, 2, 1,
            'versions', extType=ExtensionType.supported_versions)


class SrvSupportedVersionsExtension(TLSExtension):
    """
    Handling of SupportedVersion extension in SH and HRR in TLS 1.3.

    See draft-ietf-tls-tls13.

    :vartype extType: int
    :ivar extType: numeric type of the Supported Versions extension, i.e. 43

    :vartype ~.extData: bytearray
    :ivar ~.extData: raw representation of the extension payload

    :vartype ~.version: tuple
    :ivar ~.version: version selected by the server
    """

    def __init__(self):
        super(SrvSupportedVersionsExtension, self).__init__(extType=
            ExtensionType.supported_versions)
        self.version = None

    def __repr__(self):
        """
        Return programmer-readable representation of the extension.

        :rtype: str
        """
        return 'SrvSupportedVersionsExtension(version={0})'.format(self.version
            )

    def create(self, version):
        """
        Set the version supported by the server.

        :param tuple version: Version selected by server.
        :rtype: SrvSupportedVersionsExtension
        """
        pass

    @property
    def extData(self):
        """
        Raw encoding of extension data, without type and length header.

        :rtype: bytearray
        """
        pass

    def parse(self, parser):
        """
        Deserialise the extension from on-the-wire data.

        The parser should not include the type or length of extension.

        :param tlslite.util.codec.Parser parser: data to be parsed

        :rtype: SrvSupportedVersionsExtension
        """
        pass


class ClientCertTypeExtension(VarListExtension):
    """
    This class handles the (client variant of) Certificate Type extension

    See RFC 6091.

    :vartype extType: int
    :ivar extType: numeric type of Certificate Type extension, i.e. 9

    :vartype ~.extData: bytearray
    :ivar ~.extData: raw representation of the extension data

    :vartype certTypes: list of int
    :ivar certTypes: list of certificate type identifiers (each one byte long)
    """

    def __init__(self):
        """
        Create an instance of ClientCertTypeExtension

        See also: :py:meth:`create` and :py:meth:`parse`
        """
        super(ClientCertTypeExtension, self).__init__(1, 1, 'certTypes',
            ExtensionType.cert_type, CertificateType)


class ServerCertTypeExtension(IntExtension):
    """
    This class handles the Certificate Type extension (variant sent by server)
    defined in RFC 6091.

    :vartype extType: int
    :ivar extType: binary type of Certificate Type extension, i.e. 9

    :vartype ~.extData: bytearray
    :ivar ~.extData: raw representation of the extension data

    :vartype cert_type: int
    :ivar cert_type: the certificate type selected by server
    """

    def __init__(self):
        """
        Create an instance of ServerCertTypeExtension

        See also: :py:meth:`create` and :py:meth:`parse`
        """
        super(ServerCertTypeExtension, self).__init__(1, 'cert_type',
            ext_type=ExtensionType.cert_type, item_enum=CertificateType)
        self.serverType = True

    def parse(self, parser):
        """Parse the extension from on the wire format

        :param Parser p: parser with data
        """
        pass


class SRPExtension(TLSExtension):
    """
    This class handles the Secure Remote Password protocol TLS extension
    defined in RFC 5054.

    :vartype extType: int
    :ivar extType: numeric type of SRPExtension, i.e. 12

    :vartype ~.extData: bytearray
    :ivar ~.extData: raw representation of extension data

    :vartype identity: bytearray
    :ivar identity: UTF-8 encoding of user name
    """

    def __init__(self):
        """
        Create an instance of SRPExtension

        See also: :py:meth:`create` and :py:meth:`parse`
        """
        super(SRPExtension, self).__init__(extType=ExtensionType.srp)
        self.identity = None

    def __repr__(self):
        """
        Return programmer-centric description of extension

        :rtype: str
        """
        return 'SRPExtension(identity={0!r})'.format(self.identity)

    @property
    def extData(self):
        """
        Return raw data encoding of the extension

        :rtype: bytearray
        """
        pass

    def create(self, identity=None):
        """ Create and instance of SRPExtension with specified protocols

        :param bytearray identity: UTF-8 encoded identity (user name) to be
            provided
            to user. MUST be shorter than 2^8-1.

        :raises ValueError: when the identity lenght is longer than 2^8-1
        """
        pass

    def parse(self, p):
        """
        Parse the extension from on the wire format

        :param Parser p: data to be parsed

        :raises DecodeError: when the data is internally inconsistent

        :rtype: SRPExtension
        """
        pass


class NPNExtension(TLSExtension):
    """
    This class handles the unofficial Next Protocol Negotiation TLS extension.

    :vartype protocols: list of bytearrays
    :ivar protocols: list of protocol names supported by the server

    :vartype extType: int
    :ivar extType: numeric type of NPNExtension, i.e. 13172

    :vartype ~.extData: bytearray
    :ivar ~.extData: raw representation of extension data
    """

    def __init__(self):
        """
        Create an instance of NPNExtension

        See also: :py:meth:`create` and :py:meth:`parse`
        """
        super(NPNExtension, self).__init__(extType=ExtensionType.supports_npn)
        self.protocols = None

    def __repr__(self):
        """
        Create programmer-readable version of representation

        :rtype: str
        """
        return 'NPNExtension(protocols={0!r})'.format(self.protocols)

    @property
    def extData(self):
        """ Return the raw data encoding of the extension

        :rtype: bytearray
        """
        pass

    def create(self, protocols=None):
        """ Create an instance of NPNExtension with specified protocols

        :param list protocols: list of protocol names that are supported
        """
        pass

    def parse(self, p):
        """ Parse the extension from on the wire format

        :param Parser p: data to be parsed

        :raises DecodeError: when the size of the passed element doesn't match
            the internal representation

        :rtype: NPNExtension
        """
        pass


class TACKExtension(TLSExtension):
    """
    This class handles the server side TACK extension (see
    draft-perrin-tls-tack-02).

    :vartype tacks: list
    :ivar tacks: list of TACK's supported by server

    :vartype activation_flags: int
    :ivar activation_flags: activation flags for the tacks
    """


    class TACK(object):
        """
        Implementation of the single TACK
        """

        def __init__(self):
            """
            Create a single TACK object
            """
            self.public_key = bytearray(64)
            self.min_generation = 0
            self.generation = 0
            self.expiration = 0
            self.target_hash = bytearray(32)
            self.signature = bytearray(64)

        def __repr__(self):
            """
            Return programmmer readable representation of TACK object

            :rtype: str
            """
            return (
                'TACK(public_key={0!r}, min_generation={1!r}, generation={2!r}, expiration={3!r}, target_hash={4!r}, signature={5!r})'
                .format(self.public_key, self.min_generation, self.
                generation, self.expiration, self.target_hash, self.signature))

        def create(self, public_key, min_generation, generation, expiration,
            target_hash, signature):
            """
            Initialise the TACK with data
            """
            pass

        def write(self):
            """
            Convert the TACK into on the wire format

            :rtype: bytearray
            """
            pass

        def parse(self, p):
            """
            Parse the TACK from on the wire format

            :param Parser p: data to be parsed

            :rtype: TACK
            :raises DecodeError: when the internal sizes don't match the
                provided data
            """
            pass

        def __eq__(self, other):
            """
            Tests if the other object is equivalent to this TACK

            Returns False for every object that's not a TACK
            """
            if hasattr(other, 'public_key') and hasattr(other, 'min_generation'
                ) and hasattr(other, 'generation') and hasattr(other,
                'expiration') and hasattr(other, 'target_hash') and hasattr(
                other, 'signature'):
                if (self.public_key == other.public_key and self.
                    min_generation == other.min_generation and self.
                    generation == other.generation and self.expiration ==
                    other.expiration and self.target_hash == other.
                    target_hash and self.signature == other.signature):
                    return True
                else:
                    return False
            else:
                return False

    def __init__(self):
        """
        Create an instance of TACKExtension

        See also: :py:meth:`create` and :py:meth`parse`
        """
        super(TACKExtension, self).__init__(extType=ExtensionType.tack)
        self.tacks = []
        self.activation_flags = 0

    def __repr__(self):
        """
        Create a programmer readable representation of TACK extension

        :rtype: str
        """
        return 'TACKExtension(activation_flags={0!r}, tacks={1!r})'.format(self
            .activation_flags, self.tacks)

    @property
    def extData(self):
        """
        Return the raw data encoding of the extension

        :rtype: bytearray
        """
        pass

    def create(self, tacks, activation_flags):
        """
        Initialize the instance of TACKExtension

        :rtype: TACKExtension
        """
        pass

    def parse(self, p):
        """
        Parse the extension from on the wire format

        :param Parser p: data to be parsed

        :rtype: TACKExtension
        """
        pass


class SupportedGroupsExtension(VarListExtension):
    """
    Client side list of supported groups of (EC)DHE key exchage.

    See RFC4492, RFC7027 and RFC-ietf-tls-negotiated-ff-dhe-10

    :vartype groups: int
    :ivar groups: list of groups that the client supports
    """

    def __init__(self):
        """Create instance of class"""
        super(SupportedGroupsExtension, self).__init__(2, 2, 'groups',
            ExtensionType.supported_groups, GroupName)


class ECPointFormatsExtension(VarListExtension):
    """
    Client side list of supported ECC point formats.

    See RFC4492.

    :vartype formats: list of int
    :ivar formats: list of point formats supported by peer
    """

    def __init__(self):
        """Create instance of class"""
        super(ECPointFormatsExtension, self).__init__(1, 1, 'formats',
            ExtensionType.ec_point_formats, ECPointFormat)


class _SigListExt(VarSeqListExtension):
    """
    Common methods to SignatureAlgorithmsExtension and
    SignatureAlgorithmsCertExtension.
    """

    def _list_to_repr(self):
        """Return a text representation of sigalgs field.

        Override the one from ListExtension to be able to handle legacy
        signature algorithms.
        """
        pass


class SignatureAlgorithmsExtension(_SigListExt):
    """
    Client side list of supported signature algorithms.

    Should be used by server to select certificate and signing method for
    Server Key Exchange messages. In practice used only for the latter.

    See RFC5246.
    """

    def __init__(self):
        """Create instance of class"""
        super(SignatureAlgorithmsExtension, self).__init__(1, 2, 2,
            'sigalgs', ExtensionType.signature_algorithms, SignatureScheme)


class SignatureAlgorithmsCertExtension(_SigListExt):
    """
    Client side list of supported signatures in certificates.

    Should be used when the signatures supported in certificates and in TLS
    messages differ.

    See TLS1.3 RFC
    """

    def __init__(self):
        """Create instance of class."""
        super(SignatureAlgorithmsCertExtension, self).__init__(1, 2, 2,
            'sigalgs', ExtensionType.signature_algorithms_cert, SignatureScheme
            )


class PaddingExtension(TLSExtension):
    """
    ClientHello message padding with a desired size.

    Can be used to pad ClientHello messages to a desired size
    in order to avoid implementation bugs caused by certain
    ClientHello sizes.

    See RFC7685.
    """

    def __init__(self):
        """Create instance of class."""
        extType = ExtensionType.client_hello_padding
        super(PaddingExtension, self).__init__(extType=extType)
        self.paddingData = bytearray(0)

    @property
    def extData(self):
        """
        Return raw encoding of the extension.

        :rtype: bytearray
        """
        pass

    def create(self, size):
        """
        Set the padding size and create null byte padding of defined size.

        :param int size: required padding size in bytes
        """
        pass

    def parse(self, p):
        """
        Deserialise extension from on the wire data.

        :param Parser p:  data to be parsed

        :raises DecodeError: when the size of the passed element doesn't match
            the internal representation

        :rtype: TLSExtension
        """
        pass


class RenegotiationInfoExtension(VarBytesExtension):
    """
    Client and Server Hello secure renegotiation extension from RFC 5746

    Should have an empty renegotiated_connection field in case of initial
    connection
    """

    def __init__(self):
        """Create instance"""
        extType = ExtensionType.renegotiation_info
        super(RenegotiationInfoExtension, self).__init__(
            'renegotiated_connection', 1, extType)


class ALPNExtension(TLSExtension):
    """
    Handling of Application Layer Protocol Negotiation extension from RFC 7301.

    :vartype protocol_names: list of bytearrays
    :ivar protocol_names: list of protocol names acceptable or selected by peer

    :vartype extType: int
    :ivar extType: numberic type of ALPNExtension, i.e. 16

    :vartype ~.extData: bytearray
    :var ~.extData: raw encoding of the extension data
    """

    def __init__(self):
        """
        Create instance of ALPNExtension

        See also: :py:meth:`create` and :py:meth:`parse`
        """
        super(ALPNExtension, self).__init__(extType=ExtensionType.alpn)
        self.protocol_names = None

    def __repr__(self):
        """
        Create programmer-readable representation of object

        :rtype: str
        """
        return 'ALPNExtension(protocol_names={0!r})'.format(self.protocol_names
            )

    @property
    def extData(self):
        """
        Return encoded payload of the extension

        :rtype: bytearray
        """
        pass

    def create(self, protocol_names=None):
        """
        Create an instance of ALPNExtension with specified protocols

        :param list protocols: list of protocol names that are to be sent
        """
        pass

    def parse(self, parser):
        """
        Parse the extension from on the wire format

        :param Parser parser: data to be parsed as extension

        :raises DecodeError: when the encoding of the extension is self
            inconsistent

        :rtype: ALPNExtension
        """
        pass


class StatusRequestExtension(TLSExtension):
    """
    Handling of the Certificate Status Request extension from RFC 6066.

    :vartype status_type: int
    :ivar status_type: type of the status request

    :vartype responder_id_list: list of bytearray
    :ivar responder_id_list: list of DER encoded OCSP responder identifiers
        that the client trusts

    :vartype request_extensions: bytearray
    :ivar request_extensions: DER encoded list of OCSP extensions, as defined
        in RFC 2560
    """

    def __init__(self):
        """Create instance of StatusRequestExtension."""
        super(StatusRequestExtension, self).__init__(extType=ExtensionType.
            status_request)
        self.status_type = None
        self.responder_id_list = []
        self.request_extensions = bytearray()

    def __repr__(self):
        """
        Create programmer-readable representation of object

        :rtype: str
        """
        return (
            'StatusRequestExtension(status_type={0}, responder_id_list={1!r}, request_extensions={2!r})'
            .format(self.status_type, self.responder_id_list, self.
            request_extensions))

    @property
    def extData(self):
        """
        Return encoded payload of the extension.

        :rtype: bytearray
        """
        pass

    def create(self, status_type=CertificateStatusType.ocsp,
        responder_id_list=tuple(), request_extensions=b''):
        """
        Create an instance of StatusRequestExtension with specified options.

        :param int status_type: type of status returned

        :param list responder_id_list: list of encoded OCSP responder
            identifiers
            that the client trusts

        :param bytearray request_extensions: DER encoding of requested OCSP
            extensions
        """
        pass

    def parse(self, parser):
        """
        Parse the extension from on the wire format.

        :param Parser parser: data to be parsed as extension

        :rtype: StatusRequestExtension
        """
        pass


class CertificateStatusExtension(TLSExtension):
    """Handling of Certificate Status response as redefined in TLS1.3"""

    def __init__(self):
        """Create instance of CertificateStatusExtension."""
        super(CertificateStatusExtension, self).__init__(extType=
            ExtensionType.status_request)
        self.status_type = None
        self.response = None

    def create(self, status_type, response):
        """Set values of the extension."""
        pass

    def parse(self, parser):
        """Deserialise the data from on the wire representation."""
        pass

    @property
    def extData(self):
        """Serialise the object."""
        pass


class KeyShareEntry(object):
    """Handler for of the item of the Key Share extension."""

    def __init__(self):
        """Initialise the object."""
        self.group = None
        self.key_exchange = None
        self.private = None

    def create(self, group, key_exchange, private=None):
        """
        Initialise the Key Share Entry from Key Share extension.

        :param int group: ID of the key share
        :param bytearray key_exchange: value of the key share
        :param object private: private value for the given share (won't be
            encoded during serialisation)
        :rtype: KeyShareEntry
        """
        pass

    def parse(self, parser):
        """
        Parse the value from on the wire format.

        :param Parser parser: data to be parsed as extension

        :rtype: KeyShareEntry
        """
        pass

    def write(self, writer):
        """
        Write the on the wire representation of the item to writer.

        :param Writer writer: buffer to write the data to
        """
        pass

    def __repr__(self):
        """Returns human readable representation of the extension."""
        return 'KeyShareEntry(group={0},key_exchange={1})'.format(GroupName
            .toStr(self.group), repr(self.key_exchange))


class HeartbeatExtension(IntExtension):
    """
    Heartbeat extension from RFC 6520

    :type mode: int
    :ivar mode: mode if peer is allowed or nor allowed to send responses
    """

    def __init__(self):
        super(HeartbeatExtension, self).__init__(1, 'mode', ext_type=
            ExtensionType.heartbeat, item_enum=HeartbeatMode)

    def parse(self, parser):
        """Deserialise the extension from on the wire data."""
        pass


class ClientKeyShareExtension(TLSExtension):
    """
    Class for handling the Client Hello version of the Key Share extension.

    Extension for sending the key shares to server
    """

    def __init__(self):
        """Create instance of the object."""
        super(ClientKeyShareExtension, self).__init__(extType=ExtensionType
            .key_share)
        self.client_shares = None

    @property
    def extData(self):
        """
        Return the on the wire raw encoding of the extension

        :rtype: bytearray
        """
        pass

    def create(self, client_shares):
        """Set the advertised client shares in the extension."""
        pass

    def parse(self, parser):
        """
        Parse the extension from on the wire format

        :param Parser parser: data to be parsed

        :raises DecodeError: when the data does not match the definition

        :rtype: ClientKeyShareExtension
        """
        pass

    def __repr__(self):
        """Output human readable representation of the object."""
        return 'ClientKeyShareExtension(client_shares=[{0}])'.format(','.
            join(repr(i) for i in self.client_shares))


class ServerKeyShareExtension(TLSExtension):
    """
    Class for handling the Server Hello variant of the Key Share extension.

    Extension for sending the key shares to client
    """

    def __init__(self):
        """Create instance of the object."""
        super(ServerKeyShareExtension, self).__init__(extType=ExtensionType
            .key_share, server=True)
        self.server_share = None

    def create(self, server_share):
        """Set the advertised server share in the extension."""
        pass

    @property
    def extData(self):
        """Serialise the payload of the extension"""
        pass

    def parse(self, parser):
        """
        Parse the extension from on the wire format.

        :param Parser parser: data to be parsed

        :rtype: ServerKeyShareExtension
        """
        pass


class HRRKeyShareExtension(TLSExtension):
    """
    Class for handling the Hello Retry Request variant of the Key Share ext.

    Extension for notifying the client of the server selected group for
    key exchange.
    """

    def __init__(self):
        """Create instance of the object."""
        super(HRRKeyShareExtension, self).__init__(extType=ExtensionType.
            key_share, hrr=True)
        self.selected_group = None

    def create(self, selected_group):
        """Set the selected group in the extension."""
        pass

    @property
    def extData(self):
        """Serialise the payload of the extension."""
        pass

    def parse(self, parser):
        """Parse the extension from on the wire format.

        :param Parser parser: data to be parsed

        :rtype: HRRKeyShareExtension
        """
        pass


class PskIdentity(object):
    """Handling of PskIdentity from PreSharedKey Extension."""

    def __init__(self):
        """Create instance of class."""
        super(PskIdentity, self).__init__()
        self.identity = None
        self.obfuscated_ticket_age = None

    def create(self, identity, obf_ticket_age):
        """Initialise instance."""
        pass

    def write(self):
        """Serialise the object."""
        pass

    def parse(self, parser):
        """Deserialize the object from bytearray."""
        pass


class PreSharedKeyExtension(TLSExtension):
    """
    Class for handling Pre Shared Key negotiation.
    """

    def __init__(self):
        """Create instance of class."""
        super(PreSharedKeyExtension, self).__init__(extType=ExtensionType.
            pre_shared_key)
        self.identities = None
        self.binders = None

    def create(self, identities, binders):
        """Set list of offered PSKs."""
        pass

    @property
    def extData(self):
        """Serialise the payload of the extension."""
        pass

    def parse(self, parser):
        """Parse the extension from on the wire format."""
        pass


class SrvPreSharedKeyExtension(IntExtension):
    """Handling of the Pre Shared Key extension from server."""

    def __init__(self):
        """Create instance of class."""
        super(SrvPreSharedKeyExtension, self).__init__(2, 'selected',
            ext_type=ExtensionType.pre_shared_key)


class PskKeyExchangeModesExtension(VarListExtension):
    """Handling of the PSK Key Exchange Modes extension."""

    def __init__(self):
        """Create instance of class."""
        super(PskKeyExchangeModesExtension, self).__init__(1, 1, 'modes',
            ExtensionType.psk_key_exchange_modes, PskKeyExchangeMode)


class CookieExtension(VarBytesExtension):
    """Handling of the TLS 1.3 cookie extension."""

    def __init__(self):
        """Create instance."""
        ext_type = ExtensionType.cookie
        super(CookieExtension, self).__init__('cookie', 2, ext_type)


class RecordSizeLimitExtension(IntExtension):
    """Class for handling the record_size_limit extension from RFC 8449."""

    def __init__(self):
        """Create instance."""
        super(RecordSizeLimitExtension, self).__init__(2,
            'record_size_limit', ExtensionType.record_size_limit)


class SessionTicketExtension(TLSExtension):
    """
    Client and server session ticket extension from RFC 5077
    """

    def __init__(self):
        """Create instance of the object."""
        super(SessionTicketExtension, self).__init__(extType=ExtensionType.
            session_ticket)
        self.ticket = None

    @property
    def extData(self):
        """Serialise the payload of the extension."""
        pass

    def parse(self, parser):
        """
        Parse the extension from on the wire format.

        :param Parser parser: data to be parsed

        :rtype: SessionTicketExtension
        """
        pass

    def __repr__(self):
        """Return human readable representation of the extension."""
        return '{0}({1}={2!r})'.format(self.__class__.__name__, 'ticket',
            self.ticket)


TLSExtension._universalExtensions = {ExtensionType.server_name:
    SNIExtension, ExtensionType.status_request: StatusRequestExtension,
    ExtensionType.cert_type: ClientCertTypeExtension, ExtensionType.
    supported_groups: SupportedGroupsExtension, ExtensionType.
    ec_point_formats: ECPointFormatsExtension, ExtensionType.srp:
    SRPExtension, ExtensionType.signature_algorithms:
    SignatureAlgorithmsExtension, ExtensionType.alpn: ALPNExtension,
    ExtensionType.supports_npn: NPNExtension, ExtensionType.
    client_hello_padding: PaddingExtension, ExtensionType.
    renegotiation_info: RenegotiationInfoExtension, ExtensionType.heartbeat:
    HeartbeatExtension, ExtensionType.supported_versions:
    SupportedVersionsExtension, ExtensionType.key_share:
    ClientKeyShareExtension, ExtensionType.signature_algorithms_cert:
    SignatureAlgorithmsCertExtension, ExtensionType.pre_shared_key:
    PreSharedKeyExtension, ExtensionType.psk_key_exchange_modes:
    PskKeyExchangeModesExtension, ExtensionType.cookie: CookieExtension,
    ExtensionType.record_size_limit: RecordSizeLimitExtension,
    ExtensionType.session_ticket: SessionTicketExtension}
TLSExtension._serverExtensions = {ExtensionType.cert_type:
    ServerCertTypeExtension, ExtensionType.tack: TACKExtension,
    ExtensionType.key_share: ServerKeyShareExtension, ExtensionType.
    supported_versions: SrvSupportedVersionsExtension, ExtensionType.
    pre_shared_key: SrvPreSharedKeyExtension}
TLSExtension._certificateExtensions = {ExtensionType.status_request:
    CertificateStatusExtension}
TLSExtension._hrrExtensions = {ExtensionType.key_share:
    HRRKeyShareExtension, ExtensionType.supported_versions:
    SrvSupportedVersionsExtension}
