# Compatible with Python >= 3.5.
import base64
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


def ToHex(array: List[int]) -> bytes:
    """Convert array of bytes to hex string."""
    return ''.join(['{:>02x}'.format(n) for n in array]).encode()


def ToBase64(array: List[int]) -> bytes:
    """Convert array of bytes to base64 string."""
    return base64.standard_b64encode(bytes(array))


def CreateRingOfPublicKeys(size: int) -> bytes:
    """Create ring of public keys."""
    return toBytes(lib.CreateRingOfPublicKeys(size))


def CreateSignature(
        message: List[int],
        pubKeysRing: List[int],
        privateKey: List[int]) -> List[int]:
    """Extract public key form private key."""
    return toBytes(lib.CreateSignature(
        goSlice(message),
        goSlice(pubKeysRing),
        goSlice(privateKey),
    ))


def VerifySignature(
        message: List[int],
        pubKeysRing: List[int],
        signature: List[int]) -> bool:
    """Verify signature."""
    return bool(lib.VerifySignature(
        goSlice(message),
        goSlice(pubKeysRing),
        goSlice(signature),
    ))


def SignToPEM(sign: List[int]) -> List[int]:
    """Signature to PEM."""
    return toBytes(lib.SignToPEM(goSlice(sign)))


def PEMtoSign(sign: List[int]) -> List[int]:
    """PEM to signature."""
    return toBytes(lib.PEMtoSign(goSlice(sign)))


def GetPubKeyBytesSize() -> int:
    """Get size of bytes serializted public key."""
    return lib.GetPubKeyBytesSize()


ffi = FFI()

ffi.cdef("""
typedef %s GoInt;
typedef unsigned char GoUint8;
typedef struct { GoUint8* data; GoInt len; GoInt cap; } GoSlice;
typedef struct { GoInt len; GoUint8 data[]; } GoBytes;

// Key management
GoBytes* CreatePrivateKey();
GoBytes* ExtractPublicKey(GoSlice pub);
GoBytes* CreateRingOfPublicKeys(GoInt size);
GoInt GetPubKeyBytesSize();

// Ring Signature
GoBytes* CreateSignature(GoSlice message, GoSlice ring, GoSlice privKey);
GoUint8  VerifySignature(GoSlice message, GoSlice ring, GoSlice signature);
GoBytes* SignToPEM(GoSlice signBytes);
GoBytes* PEMtoSign(GoSlice signBytes);

""" % ("long" if sys.maxsize > 2**32 else "int"))


path = os.path.dirname(__file__)
if path == "":
    path = "."
lib = ffi.dlopen(os.path.join(path, "lirisilib.so"))
