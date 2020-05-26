import random

from lirisi import (CreatePrivateKey, CreateRingOfPublicKeys, CreateSignature, GetPubKeyBytesSize, ExtractPublicKey,
                    PEMtoSign, SignToPEM, ToBase64, ToHex, VerifySignature)


# ---------------------------------------
# Create your private key.

privateKey = CreatePrivateKey()
print("Your private key:")
print(ToHex(privateKey).decode())

# Output:
# 74aa6a01921f598a384b7c3896e9cf6264c207b1b8c045042b7ea58eef6f65b6

# ---------------------------------------
# Extract public key.

publicKey = ExtractPublicKey(privateKey)
print("\nYour public key:")
print(ToBase64(publicKey).decode())

# Output:
# BLP66/E9HNhdao1p/7/Aw6V+8BLB0fiKRPL4MR/vJV+nEHdquzXpWThL+Hhpuqel/7R6HpuUEfIHoiNn4clmVB8=

# ---------------------------------------
# Create the ring of fake public keys.

pubList = []
ring = CreateRingOfPublicKeys(9)

# Append your public key.
ring += publicKey

# Randomly shuffle list of public keys.
size = GetPubKeyBytesSize()
ringPubs = []
for pos in range(int(len(ring) / size)):
    i = pos * size
    ringPubs.append(ring[i:i+size])
random.shuffle(ringPubs)

# Concat shuffled keys.
ringPubKeys = []
for chunk in ringPubs:
    ringPubKeys.extend(chunk)

# Prepare public keys for save.
pubList = []
for chunk in ringPubs:
    pubList.append(ToBase64(chunk).decode())

print("\nRing of public keys:")
print('\n'.join(pubList))

# Output:
# BECA9qR+T+bePvJXVVYUA9GLYWfQ799/5EwlN6DH+VygPAZ3JtHxCPWpO3VdA9DALuids39Mb3/d1JYubU1cxg8=
# BNoLhSi/zHveaI+fHSSGVjUwb6PInRIm7GO1k4hWkkXo9wHtpTwks+yzN7ZZzElTpqBUtfIMM1UtAdhlhQVUJ+4=
# BJGTB+5MlE84LrQPDPr+7zVlGlnsF26QJkYKej4A3VFq8ilx5ZV1Gy4ZEM/F6Tn5LrzJ5Lw2I51eXOWGPu2AHbI=
# BKjS6IXUBJ2wIDKxxhkKXfhBCUSCQB37wHjZK0WXQUHTnZCxCQqtggpRAlPkfXVjFBMTJZkTniTFDI/293A3yBk=
# BB5dsoqdrTdqANzp7MRSZrhbLXF3V5AcIzfmy3/HaKSmGVzdpDw3dUUTWjz5z2ZKI/pWAZV0KJBveMV757Uxa7Q=
# BGBtFDAteGv8atveX+0pn86cQXyCakn2pXlbszUup51wwrTH57DbzjlYfaowH4lk6++TnAaLpJNCDKI4SH67A/g=
# BLP66/E9HNhdao1p/7/Aw6V+8BLB0fiKRPL4MR/vJV+nEHdquzXpWThL+Hhpuqel/7R6HpuUEfIHoiNn4clmVB8=
# BIplYHkY1EqeTCmsoieGiNVc2wBTVPcQSmb/tGVRg4fjy0ZClWPzdaXW2N2wHI4vVj453RpdG2+QzZmjTuaaDNk=
# BIBjSmlHDqmfLuI9AMw6+yUg+ms0ctRc0u35tadiDzIT0jKDotTLXm2JTdpiKDzoJJDY0Zw/z3D6Jgx/UVCMgwE=
# BPOnZeQoVH/nvDsL4I/NXUtAbabiGbh6k3atTpMyxgmXQWTNc4TQKiFGvbh3E0JzQqzjHV3n+UxGbr7oTio3HFs=


# ---------------------------------------
# Prepare message to sign.
# It is a list of bytes - bytearray.
# message = [ord(c) for c in "Hello world!"]
message = "Hello world!".encode()

# ---------------------------------------
# Make signature.
sign = CreateSignature(message, ringPubKeys, privateKey)
pemBytes = SignToPEM(sign)
print("\nSignature in PEM:")
print("".join([chr(c) for c in pemBytes]))

# Output:
# -----BEGIN RING SIGNATURE-----
# KeyImage: n3eMbqe1K+ngj0eKJ2+1so3uwwEIaie7HPCUKLc0/jutSM14cdqpRTZqvrgLw1Mfh8J0ylvqJI3DI52G8SmkpQ==

# QklJQm9KOTNqRzZudFN2cDRJOUhpaWR2dGJLTjdzTUJDR29udXh6d2xDaTNOUDQ3
# clVqTmVISGFxVVUyYXI2NEM4TlRINGZDZE1wYjZpU053eU9kaHZFcHBLV0xrTVR5
# RXIzRkhiNVVkbnkxM3Y4NkEyZE5LU1hna282RDhMYXNxTExNRHBOaG1kZTdzT2Rs
# VHo1M1E3eXNhMUFZeUc4SENQUmsreWR0YldYSmRINFdCMjlMdEhpazc2My90WjJW
# Y0NZVUgvMmh2NnZFL0tlSzhOdHIybFZnMkcrOTExWHdLd3ZSZUFNdkppOEo0dGJB
# V1l2NXhYallOZVZuN2lZc24zU1ZMYU5RNmFZcHppcjRDSkpXUFNHa3dIMkpXeHp1
# Q3NPTlNlclo5R0JqdkdNdlZZYTNXSnNhdHpESWR4QjlKQ0tQUHlzSFJTWkZUam9a
# djBia1JldlBGSGwzbExuVUZ3akRVMGlwTGVBTm1RVnNwR2svaW5ZdUJyTFpFQVQr
# aUZoTkRvVlFKVDF3cElKWER6Q0hSWFphUElRaDgyL2hGZGZFb0tRdmg1Q01YWG90
# TEdNUE5JVnU2M0RjMTNlM0Q1aU5SKzZ2Kzd6Wm8yVUdwNTNSdStlbFRvdGdKaEVh
# OGFKTWlQdVpOT3hnMithejNRb1k2UUtNMFZDZC8rNU9GTUt3aFBab1FXbHJ1aVFI
# RCtxTU1ad2VuWUx0eW9JS1RNRjVsMVorQjNFTTl3bkg=
# -----END RING SIGNATURE-----

# ---------------------------------------
# Load signature bytes from PEM.
signFromPEM = PEMtoSign(pemBytes)

# ---------------------------------------
# Verify signature.
result = VerifySignature(message, ringPubKeys, signFromPEM)
print("Result of verification (true):", result)
# Output:
# Result of verification (true): True

result = VerifySignature([ord(c) for c in "Hello fokls!"], ringPubKeys, signFromPEM)
print("Invalid verification (false):", result)
# Output:
# Invalid verification (false): False
