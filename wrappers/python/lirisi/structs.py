import ctypes


GoBoolean = ctypes.c_ubyte


class GoBytes(ctypes.Structure):
    """GoBytes represents go type []byte."""
    _fields_ = [
        ("data", ctypes.POINTER(ctypes.c_ubyte)),
        ("len", ctypes.c_longlong),
        ("cap", ctypes.c_longlong),
    ]


class GoBytesArray(ctypes.Structure):
    """GoBytesArray represents go type [][]byte."""
    _fields_ = [
        ("data", ctypes.POINTER(GoBytes)),
        ("len", ctypes.c_longlong),
        ("cap", ctypes.c_longlong),
    ]


class GoString(ctypes.Structure):
    """GoString represents go type string."""
    _fields_ = [
        ("p", ctypes.c_char_p),
        ("n", ctypes.c_int)
    ]


class GoStringsArray(ctypes.Structure):
    """GoStringsArray represents go type []string."""
    _fields_ = [
        ("data", ctypes.POINTER(GoString)),
        ("len", ctypes.c_longlong),
        ("cap", ctypes.c_longlong),
    ]


class BuffBytes(ctypes.Structure):
    """BuffBytes represents go type unsafe.Pointer of C.CBytes."""
    _fields_ = [
        ("data", ctypes.POINTER(ctypes.c_ubyte)),
    ]
