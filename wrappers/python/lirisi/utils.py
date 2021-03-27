import ctypes
from typing import List, Sequence

from .exceptions import EXCEPTION_BY_STATUS
from .structs import BuffBytes, GoBytes, GoBytesArray, GoString, GoStringsArray


def goBytes(octets: bytes) -> GoBytes:
    """Make GoBytes instance with array of bytes."""
    length = len(octets)
    return GoBytes((ctypes.c_ubyte * length)(*octets), length, length)


def goBytesArray(array: Sequence[bytes]) -> GoBytesArray:
    """Make GoBytesArray instance, that is the GoSlices array."""
    data = []
    for values in array:
        data.append(goBytes(values))
    length = len(data)
    return GoBytesArray((GoBytes * length)(*data), length, length)


def goString(text: str) -> GoString:
    """Cast python string to GoString."""
    octets = text.encode("UTF-8")
    return GoString(ctypes.c_char_p(octets), len(octets))


def goStringsArray(array: Sequence[str]) -> GoStringsArray:
    """Make GoStringsArray instance with array of UTF-8 bytes."""
    data = []
    for values in array:
        data.append(goString(values))
    length = len(data)
    return GoStringsArray((GoString * length)(*data), length, length)


def readPointer(buff: BuffBytes) -> (int, List[int]):
    """Read response data and status from unsafe.Pointer of Go C.CBytes."""
    status = int.from_bytes(buff.data[:8], byteorder='little')
    size = int.from_bytes(buff.data[:16][8:], byteorder='little')
    data = buff.data[:size+16][16:]
    return status, data


def readFromPointer(buff: BuffBytes) -> (int, List[List[int]]):
    """Read response status and data from unsafe.Pointer of Go C.CBytes."""
    data = []
    size = 8
    status = int.from_bytes(buff.data[:size], byteorder='little')
    length = int.from_bytes(buff.data[:size+size][size:], byteorder='little')
    frm, to = size * 2, size * 2
    for i in range(length):
        frm, to = frm + size, frm
        bufflen = int.from_bytes(buff.data[:frm][to:], byteorder='little')
        frm, to = frm + bufflen, frm
        data.append(bytes(buff.data[:frm][to:]))
    return status, data


def toListBytes(buff: BuffBytes) -> List[bytes]:
    """Get response from buffer as bytes."""
    status, data = readFromPointer(buff)
    if status > 0:
        raise EXCEPTION_BY_STATUS[status]
    return data


def toBytes(buff: BuffBytes) -> bytes:
    """Get response from buffer as bytes."""
    status, octets = readPointer(buff)
    if status > 0:
        raise EXCEPTION_BY_STATUS[status](bytes(octets).decode('UTF-8'))
    return bytes(octets)


def toStr(buff: BuffBytes) -> str:
    """Get response from buffer as string."""
    return toBytes(buff).decode('UTF-8')
