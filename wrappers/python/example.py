from typing import Callable, List

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from lirisi import (CreateSignature, DerivePublicKey, FoldPublicKeys,
                    GeneratePrivateKey, LirisiException, PublicKeysDigest,
                    PublicKeyXYCoordinates, SignatureKeyImage,
                    UnfoldPublicKeys, VerifySignature)


def createPublicKeyList(backend: Callable, curve: ec.EllipticCurve, size: int) -> List[bytes]:
    public_keys_pem = []
    for i in range(size):
        private_key = ec.generate_private_key(curve, backend)
        public_key = private_key.public_key()
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        public_keys_pem.append(pem)
    return public_keys_pem


def main():
    backend = default_backend()

    # Create private key. Default curve type is "prime256v1".
    priateKeyPem = GeneratePrivateKey()
    print(priateKeyPem.decode())

    # Create public key.
    publicKeyPem = DerivePublicKey(priateKeyPem)
    print(publicKeyPem.decode())

    # Choose curve type.
    curve = ec.SECP256R1()

    # Creating public keys as a simulation of keys supplied by other signers.
    public_keys_pem = createPublicKeyList(backend, curve, 9)

    # Create your private key.
    private_key = ec.generate_private_key(curve, backend)
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    print(private_key_pem.decode())

    # Add your public key to other public keys.
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    public_keys_pem.append(public_key_pem)

    coordinates = PublicKeyXYCoordinates(public_key_pem)
    print("Public key coordinates (bytes):\n", coordinates, "\n")

    # Create the content of file with public keys.
    foldedPublicKeys = FoldPublicKeys(public_keys_pem)
    print(foldedPublicKeys.decode())

    # Display fingerprint of public keys.
    digest = PublicKeysDigest(foldedPublicKeys, True)
    print("Public keys digest:", digest.decode())
    print()

    # Make signature.
    signature = CreateSignature(foldedPublicKeys, private_key_pem, b'Hello, world!')
    print(signature.decode())

    # Verify signature.
    if VerifySignature(foldedPublicKeys, signature, b'Hello, world!'):
        print("Signature verified OK")
    else:
        print("Signature verification Failure")
    print()

    # Display Signer identifier KeyImage.
    key_image = SignatureKeyImage(signature, True)
    print("KeyImage:", key_image)
    print()

    unfolded_keys = UnfoldPublicKeys(foldedPublicKeys)
    for pos, key in enumerate(unfolded_keys):
        print("public-key-{:>02d}.pem".format(pos + 1))
        print(key.decode())


if __name__ == "__main__":
    try:
        main()
    except LirisiException as err:
        print(err)
