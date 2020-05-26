import base64
import ctypes
import os
from typing import List


class GoSlice(ctypes.Structure):
    _fields_ = [
        ("data", ctypes.POINTER(ctypes.c_ubyte)),
        ("len", ctypes.c_longlong),
        ("cap", ctypes.c_longlong),
    ]


class BuffBytes(ctypes.Structure):
    _fields_ = [
        ("data", ctypes.POINTER(ctypes.c_ubyte)),
    ]


# API - Main Library functions.

def CreatePrivateKey() -> List[int]:
    """Create private key."""
    lib.CreatePrivateKey.restype = BuffBytes
    return toBytes(lib.CreatePrivateKey())


def ExtractPublicKey(privateKey: List[int]) -> List[int]:
    """Extract public key form private key."""
    lib.ExtractPublicKey.argtypes = [GoSlice]
    lib.ExtractPublicKey.restype = BuffBytes
    return toBytes(lib.ExtractPublicKey(goSlice(privateKey)))


def CreateRingOfPublicKeys(size: int) -> bytes:
    """Create ring of public keys."""
    lib.CreateRingOfPublicKeys.argtypes = [ctypes.c_longlong]
    lib.CreateRingOfPublicKeys.restype = BuffBytes
    return toBytes(lib.CreateRingOfPublicKeys(size))


def CreateSignature(message: List[int], pubKeysRing: List[int], privateKey: List[int]) -> List[int]:
    """Extract public key form private key."""
    lib.CreateSignature.argtypes = [GoSlice, GoSlice, GoSlice]
    lib.CreateSignature.restype = BuffBytes
    return toBytes(lib.CreateSignature(
        goSlice(message),
        goSlice(pubKeysRing),
        goSlice(privateKey),
    ))


def VerifySignature(message: List[int], pubKeysRing: List[int], signature: List[int]) -> bool:
    """Verify signature."""
    lib.VerifySignature.argtypes = [GoSlice, GoSlice, GoSlice]
    return bool(lib.VerifySignature(
        goSlice(message),
        goSlice(pubKeysRing),
        goSlice(signature),
    ))


def SignToPEM(sign: List[int]) -> List[int]:
    """Signature to PEM."""
    lib.SignToPEM.argtypes = [GoSlice]
    lib.SignToPEM.restype = BuffBytes
    return toBytes(lib.SignToPEM(goSlice(sign)))


def PEMtoSign(sign: List[int]) -> List[int]:
    """PEM to signature."""
    lib.PEMtoSign.argtypes = [GoSlice]
    lib.PEMtoSign.restype = BuffBytes
    return toBytes(lib.PEMtoSign(goSlice(sign)))


def GetPubKeyBytesSize() -> int:
    """Get size of bytes serializted public key."""
    return lib.GetPubKeyBytesSize()


# Private module functions

def goSlice(values: List[int]) -> GoSlice:
    """Make GoClice instance with aaray of bytes."""
    length = len(values)
    return GoSlice((ctypes.c_ubyte * length)(*values), length, length)


def toBytes(buff: BuffBytes) -> List[int]:
    """Create array of bytes from buffer."""
    size = int.from_bytes(buff.data[:8], byteorder='little')
    return buff.data[:size+8][8:]


# Extra functions for convenient programmers.

def ToHex(array: List[int]) -> bytes:
    """Convert array of bytes to hex string."""
    return ''.join(['{:>02x}'.format(n) for n in array]).encode()


def ToBase64(array: List[int]) -> bytes:
    """Convert array of bytes to base64 string."""
    return base64.standard_b64encode(bytes(array))


# Init library.

path = os.path.dirname(__file__)
if path == "":
    path = "."
lib = ctypes.cdll.LoadLibrary(os.path.join(path, "lirisilib.so"))
