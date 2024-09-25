"""Helper package for handling fragmentation of messages."""
from __future__ import generators
from .utils.codec import Parser
from .utils.deprecations import deprecated_attrs, deprecated_params


@deprecated_attrs({'add_static_size': 'addStaticSize', 'add_dynamic_size':
    'addDynamicSize', 'add_data': 'addData', 'get_message': 'getMessage',
    'clear_buffers': 'clearBuffers'})
class Defragmenter(object):
    """
    Class for demultiplexing TLS messages.

    Since the messages can be interleaved and fragmented between each other
    we need to cache not complete ones and return in order of urgency.

    Supports messages with given size (like Alerts) or with a length header
    in specific place (like Handshake messages).

    :ivar priorities: order in which messages from given types should be
        returned.
    :ivar buffers: data buffers for message types
    :ivar decoders: functions which check buffers if a message of given type
        is complete
    """

    def __init__(self):
        """Set up empty defregmenter"""
        self.priorities = []
        self.buffers = {}
        self.decoders = {}

    @deprecated_params({'msg_type': 'msgType'})
    def add_static_size(self, msg_type, size):
        """Add a message type which all messages are of same length"""
        self.priorities.append(msg_type)
        self.buffers[msg_type] = bytearray()
        self.decoders[msg_type] = lambda x: len(x) >= size

    @deprecated_params({'msg_type': 'msgType', 'size_offset': 'sizeOffset',
        'size_of_size': 'sizeOfSize'})
    def add_dynamic_size(self, msg_type, size_offset, size_of_size):
        """Add a message type which has a dynamic size set in a header"""
        self.priorities.append(msg_type)
        self.buffers[msg_type] = bytearray()
        def decoder(x):
            if len(x) < size_offset + size_of_size:
                return False
            size = Parser(x[size_offset:size_offset+size_of_size]).getFixBytes(size_of_size)
            return len(x) >= size_offset + size_of_size + size
        self.decoders[msg_type] = decoder

    @deprecated_params({'msg_type': 'msgType'})
    def add_data(self, msg_type, data):
        """Adds data to buffers"""
        if msg_type in self.buffers:
            self.buffers[msg_type].extend(data)

    def get_message(self):
        """Extract the highest priority complete message from buffer"""
        for msg_type in self.priorities:
            if msg_type in self.buffers and self.decoders[msg_type](self.buffers[msg_type]):
                message = bytes(self.buffers[msg_type])
                self.buffers[msg_type] = bytearray()
                return (msg_type, message)
        return None

    def clear_buffers(self):
        """Remove all data from buffers"""
        for msg_type in self.buffers:
            self.buffers[msg_type] = bytearray()

    def is_empty(self):
        """Return True if all buffers are empty."""
        return all(len(buffer) == 0 for buffer in self.buffers.values())
