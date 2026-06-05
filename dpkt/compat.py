"""Python 3 compatibility shims.

These functions exist to ease the Python 2 to 3 transition.  For Python 3
they are thin wrappers around the built-in equivalents.
"""
from struct import pack, unpack
from io import BytesIO


def compat_ord(char):
    """Return the integer value of a byte.

    In Python 3, indexing a bytes object already returns an int.
    """
    return char


compat_izip = zip


def iteritems(d, **kw):
    """Iterate over dictionary items."""
    return iter(d.items(**kw))


# python3 will return an int if you round to 0 decimal places
intround = round


def ntole(v):
    """convert a 2-byte word from the network byte order (big endian) to little endian;
    replaces socket.ntohs() to work on both little and big endian architectures
    """
    return unpack('<H', pack('!H', v))[0]


def ntole64(v):
    """
    Convert an 8-byte word from network byte order (big endian) to little endian.
    """
    return unpack('<Q', pack('!Q', v))[0]


def isstr(s):
    """True if 's' is an instance of str."""
    return isinstance(s, str)
