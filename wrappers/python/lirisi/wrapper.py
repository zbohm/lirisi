# Compatible with Python >= 3.5.
import os
import sys
from typing import Any, List, NewType

from cffi import FFI

# <class '_cffi_backend.CData'> <cdata 'GoBytes *'>
CData = NewType('CData', Any)
# <class '_cffi_backend.CDataOwn'> <cdata 'GoSlice' owning NNN bytes>
CDataOwn = NewType('CDataOwn', Any)


def toBytes(pointer: CData) -> List[int]:
    return [pointer.data[i] for i in range(pointer.len)]


def toChars(pointer: CData) -> List[str]:
    return [chr(n) for n in toBytes(pointer)]


def goSlice(values: List[int]) -> CDataOwn:
    return ffi.new("GoSlice*", {'data': ffi.new("GoUint8[]", values), 'len': len(values), 'cap': len(values)})[0]


def CreatePrivateKey() -> List[int]:
    """Create private key."""
    return toBytes(lib.CreatePrivateKey())


def ExtractPublicKey(privateKey: List[int]) -> List[int]:
    """Extract public key form private key."""
    return toBytes(lib.ExtractPublicKey(goSlice(privateKey)))


ffi = FFI()

ffi.cdef("""
typedef %s GoInt;
typedef unsigned char GoUint8;
typedef struct { void* data; GoInt len; GoInt cap; } GoSlice;
typedef struct { GoInt len; GoUint8 data[]; } GoBytes;

// Key management
GoBytes* CreatePrivateKey();
GoBytes* ExtractPublicKey(GoSlice pub);

// Ring Signature
""" % ("long" if sys.maxsize > 2**32 else "int"))

path = os.path.dirname(__file__)
if path == "":
    path = "."
lib = ffi.dlopen(os.path.join(path, "lirisilib.so"))
