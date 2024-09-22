"""Wrapper around the socket.socket interface that provides buffering"""
from collections import deque


class BufferedSocket(object):
    """
    Socket that will buffer reads and writes to a real socket object

    When buffer_writes is enabled, writes won't be passed to the real socket
    until flush() is called.

    Not multithread safe.

    :vartype buffer_writes: boolean
    :ivar buffer_writes: whether to buffer data writes, False by default
    """

    def __init__(self, socket):
        """Associate socket with the object"""
        self.socket = socket
        self._write_queue = deque()
        self.buffer_writes = False
        self._read_buffer = bytearray()

    def send(self, data):
        """Send data to the socket"""
        pass

    def sendall(self, data):
        """Send data to the socket"""
        pass

    def flush(self):
        """Send all buffered data"""
        pass

    def recv(self, bufsize):
        """Receive data from socket (socket emulation)"""
        pass

    def getsockname(self):
        """Return the socket's own address (socket emulation)."""
        pass

    def getpeername(self):
        """
        Return the remote address to which the socket is connected

        (socket emulation)
        """
        pass

    def settimeout(self, value):
        """Set a timeout on blocking socket operations (socket emulation)."""
        pass

    def gettimeout(self):
        """
        Return the timeout associated with socket operations

        (socket emulation)
        """
        pass

    def setsockopt(self, level, optname, value):
        """Set the value of the given socket option (socket emulation)."""
        pass

    def shutdown(self, how):
        """Shutdown the underlying socket."""
        pass

    def close(self):
        """Close the underlying socket."""
        pass
