"""Abstract Syntax Notation One (ASN.1) parsing"""
from .codec import Parser


class ASN1Type(object):
    """
    Class that represents the ASN.1 type bit octet.
    Consists of a class (universal(0), application(1), context-specific(2)
    or private(3)), boolean value that indicates if a type is constructed or
    primitive and the ASN1 type itself.

    :vartype bytes: bytearray
    :ivar field: bit octet

    :vartype tagClass: int
    :ivar tagClass: type's class

    :vartype isPrimitive: int
    :ivar isPrimitive: equals to 0 if the type is primitive, 1 if not

    :vartype tagId: int
    :ivar tagId: ANS1 tag number
    """

    def __init__(self, tag_class, is_primitive, tag_id):
        self.tag_class = tag_class
        self.is_primitive = is_primitive
        self.tag_id = tag_id


class ASN1Parser(object):
    """
    Parser and storage of ASN.1 DER encoded objects.

    :vartype length: int
    :ivar length: length of the value of the tag
    :vartype value: bytearray
    :ivar value: literal value of the tag
    """

    def __init__(self, bytes):
        """Create an object from bytes.

        :type bytes: bytearray
        :param bytes: DER encoded ASN.1 object
        """
        p = Parser(bytes)
        self.type = self._parse_type(p)
        self.length = self._getASN1Length(p)
        self.value = p.getFixBytes(self.length)

    def getChild(self, which):
        """
        Return n-th child assuming that the object is a SEQUENCE.

        :type which: int
        :param which: ordinal of the child to return

        :rtype: ASN1Parser
        :returns: decoded child object
        """
        if self.type.is_primitive:
            raise ValueError("Cannot get child of a primitive type")
        
        children = self._parse_children()
        if which >= len(children):
            raise IndexError("Child index out of range")
        
        return ASN1Parser(children[which])

    def getChildCount(self):
        """
        Return number of children, assuming that the object is a SEQUENCE.

        :rtype: int
        :returns: number of children in the object
        """
        if self.type.is_primitive:
            return 0
        return len(self._parse_children())

    def getChildBytes(self, which):
        """
        Return raw encoding of n-th child, assume self is a SEQUENCE

        :type which: int
        :param which: ordinal of the child to return

        :rtype: bytearray
        :returns: raw child object
        """
        if self.type.is_primitive:
            raise ValueError("Cannot get child of a primitive type")
        
        children = self._parse_children()
        if which >= len(children):
            raise IndexError("Child index out of range")
        
        return children[which]

    @staticmethod
    def _getASN1Length(p):
        """Decode the ASN.1 DER length field"""
        first_byte = p.get(1)[0]
        if first_byte & 0x80 == 0:
            return first_byte
        else:
            length_bytes = first_byte & 0x7F
            return int.from_bytes(p.get(length_bytes), byteorder='big')

    @staticmethod
    def _parse_type(parser):
        """Decode the ASN.1 DER type field"""
        type_byte = parser.get(1)[0]
        tag_class = (type_byte & 0xC0) >> 6
        is_primitive = (type_byte & 0x20) == 0
        tag_id = type_byte & 0x1F
        
        if tag_id == 0x1F:
            # Long form
            tag_id = 0
            while True:
                next_byte = parser.get(1)[0]
                tag_id = (tag_id << 7) | (next_byte & 0x7F)
                if next_byte & 0x80 == 0:
                    break
        
        return ASN1Type(tag_class, is_primitive, tag_id)

    def _parse_children(self):
        """Parse children of a constructed type"""
        children = []
        p = Parser(self.value)
        while p.hasMoreBytes():
            child_type = self._parse_type(p)
            child_length = self._getASN1Length(p)
            child_value = p.getFixBytes(child_length)
            children.append(child_type.bytes + child_length.to_bytes((child_length.bit_length() + 7) // 8, byteorder='big') + child_value)
        return children
