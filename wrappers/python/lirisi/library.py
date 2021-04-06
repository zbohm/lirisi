# # Library for Python
# Note: To show as a literar code documentation compile this code by [pycco](https://github.com/pycco-docs/pycco):
# ```
# $ pycco wrappers/python/lirisi/library.py
# $ firefox docs/library.html
# ```

import ctypes
import os
from typing import List, Sequence

from .exceptions import EXCEPTION_BY_STATUS
from .structs import (BuffBytes, GoBoolean, GoBytes, GoBytesArray, GoString,
                      GoStringsArray)
from .utils import (goBytes, goBytesArray, goString, goStringsArray, toBytes,
                    toListBytes, toStr)

# API - Main Library functions.


def GeneratePrivateKey(curveName: str = "prime256v1", outFormat: str = "PEM") -> bytes:
    """## GeneratePrivateKey

    Generate private key in PEM or DER.

    ```python
    from lirisi import GeneratePrivateKey

    priateKeyPem = GeneratePrivateKey()
    print(priateKeyPem.decode())
    ```
    """
    lib.GeneratePrivateKey.argtypes = [GoString, GoString]
    lib.GeneratePrivateKey.restype = BuffBytes
    return toBytes(lib.GeneratePrivateKey(goString(curveName), goString(outFormat)))


def DerivePublicKey(privateKey: bytes, outFormat: str = "PEM") -> bytes:
    """## DerivePublicKey

    Derive public key from private key.

    ```python
    from lirisi import GeneratePrivateKey, DerivePublicKey

    priateKeyPem = GeneratePrivateKey()
    publicKeyPem = DerivePublicKey(priateKeyPem)
    print(publicKeyPem.decode())
    ```
    """
    lib.DerivePublicKey.argtypes = [GoBytes, GoString]
    lib.DerivePublicKey.restype = BuffBytes
    return toBytes(lib.DerivePublicKey(goBytes(privateKey), goString(outFormat)))


def SignatureKeyImage(signature_body: bytes, separator: bool = False) -> str:
    """## SignatureKeyImage

    Show signature key image.

    ```python
    from lirisi import LirisiException, SignatureKeyImage
    path = "prime256v1-signature.pem"
    with open(path, 'rb') as handle:
        try:
            key_image = SignatureKeyImage(handle.read(), True)
        except LirisiException as err:
            print(err)
    print(key_image)
    ```
    """
    lib.SignatureKeyImage.argtypes = [GoBytes, GoBoolean]
    lib.SignatureKeyImage.restype = BuffBytes
    return toStr(lib.SignatureKeyImage(goBytes(signature_body), GoBoolean(separator)))


def FoldPublicKeys(
            pubKeysContent: Sequence[bytes],
            hashName: str = 'sha3-256',
            outFormat: str = 'PEM',
            order: str = 'hashes'
        ) -> bytes:
    """## FoldPublicKeys

    Fold public keys from array of public contents into one content. Output format is `PEM` or `DER`.

    ```python
    import os
    from lirisi import LirisiException, FoldPublicKeys

    pubKeysContent = []

    folder = "prime256v1-pubic-keys/"
    for filename in os.listdir(folder):
        pubKeysContent.append(open(os.path.join(folder, filename), 'rb').read())
    foldedPublicKeys = FoldPublicKeys(pubKeysContent)
    print(foldedPublicKeys.decode())
    ```
    """
    lib.FoldPublicKeys.argtypes = [GoBytesArray, GoString, GoString, GoString]
    lib.FoldPublicKeys.restype = BuffBytes
    return toBytes(lib.FoldPublicKeys(
        goBytesArray(pubKeysContent),
        goString(hashName),
        goString(outFormat),
        goString(order),
    ))


def UnfoldPublicKeys(foldedPublicKeys: Sequence[bytes], outFormat: str = 'PEM') -> List[bytes]:
    """## UnfoldPublicKeys

    Separate folded public keys into files. Output format is `PEM` or `DER`.

    ```python
    from lirisi import UnfoldPublicKeys

    public_keys = open("prime256v1-keys.pem", "rb").read()
    unfolded_keys = UnfoldPublicKeys(public_keys)
    for pos, key in enumerate(unfolded_keys):
        print("public-key-{:>02d}.pem".format(pos + 1))
        print(key.decode())
    ```
    """
    lib.UnfoldPublicKeys.argtypes = [GoBytes, GoString]
    lib.UnfoldPublicKeys.restype = BuffBytes
    return toListBytes(lib.UnfoldPublicKeys(goBytes(foldedPublicKeys), goString(outFormat)))


def PublicKeysDigest(foldedPublicKeys: Sequence[bytes], separator: bool = False) -> bytes:
    """## PublicKeysDigest

    PublicKeysDigest returns digest of public keys.
    ```python
    from lirisi import PublicKeysDigest

    public_keys = open("prime256v1-keys.pem", "rb").read()
    digest = PublicKeysDigest(public_keys)
    print(digest.decode())
    ```
    """
    lib.PublicKeysDigest.argtypes = [GoBytes, GoBoolean]
    lib.PublicKeysDigest.restype = BuffBytes
    return toBytes(lib.PublicKeysDigest(goBytes(foldedPublicKeys), GoBoolean(separator)))


def PublicKeyXYCoordinates(foldedPublicKeys: Sequence[bytes], separator: bool = False) -> bytes:
    """## PublicKeyXYCoordinates

    PublicKeyXYCoordinates returns X,Y coordinates of public key.
    ```python
    from lirisi import PublicKeyXYCoordinates

    public_key = open("public-key.pem", "rb").read()
    coordinates = PublicKeyXYCoordinates(public_key)
    print(coordinates)
    ```
    """
    lib.PublicKeyXYCoordinates.argtypes = [GoBytes]
    lib.PublicKeyXYCoordinates.restype = BuffBytes
    return toBytes(lib.PublicKeyXYCoordinates(goBytes(foldedPublicKeys)))


def CreateSignature(
            foldedPublicKeys: bytes,
            privateKeyContent: bytes,
            message: bytes,
            caseIdentifier: bytes = '',
            outFormat: str = 'PEM',
        ) -> bytes:
    """## CreateSignature

    Create ring signature. Output format is `PEM` or `DER`.

    ```python
    from lirisi import CreateSignature

    public_keys = open("prime256v1-keys.pem", "rb").read()
    private_key = open("private-key-08.pem", "rb").read()

    signature = CreateSignature(
        public_keys, private_key, b'Hello, world!')
    print("signature:", signature.decode())
    ```
    """
    lib.CreateSignature.argtypes = [GoBytes, GoBytes, GoBytes, GoBytes, GoString]
    lib.CreateSignature.restype = BuffBytes
    return toBytes(lib.CreateSignature(
        goBytes(foldedPublicKeys),
        goBytes(privateKeyContent),
        goBytes(message),
        goBytes(caseIdentifier),
        goString(outFormat),
    ))


def VerifySignature(
            foldedPublicKeys: bytes,
            signature: bytes,
            message: bytes,
            caseIdentifier: bytes = '',
        ) -> bool:
    """## VerifySignature

    Verify signature.

    ```python
    from lirisi import VerifySignature

    public_keys = open("prime256v1-keys.pem", "rb").read()
    signature = open("prime256v1-signature.pem", "rb").read()

    result = VerifySignature(
        public_keys, signature, b'Hello, world!')
    print("result:", result)
    ```
    """
    lib.VerifySignature.argtypes = [GoBytes, GoBytes, GoBytes, GoBytes]
    lib.VerifySignature.restype = GoBoolean
    status = lib.VerifySignature(
        goBytes(foldedPublicKeys),
        goBytes(signature),
        goBytes(message),
        goBytes(caseIdentifier),
    )
    if status not in (0, 9):
        raise EXCEPTION_BY_STATUS[status]()
    return status == 0


# Init library.

path = os.path.dirname(__file__)
if path == "":
    path = "."
lib = ctypes.cdll.LoadLibrary(os.path.join(path, "lirisilib.so"))
