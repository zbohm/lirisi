class LirisiException(Exception):
    """Basic Lirisi exception."""


class PrivateKeyNotFitPublic(LirisiException):
    """Private key not fit public."""


class InsufficientNumberOfPublicKeys(LirisiException):
    """Insufficient number of public keys."""


class PrivateKeyPositionOutOfRange(LirisiException):
    """Private key position out of range."""


class PrivateKeyNotFoundAmongPublicKeys(LirisiException):
    """Private key not found among public keys."""


class UnexpectedCurveType(LirisiException):
    """Unexpected curve type."""


class UnexpectedHashType(LirisiException):
    """Unexpected hash type."""


class IncorrectNumberOfSignatures(LirisiException):
    """Incorrect number of signatures."""


class InvalidKeyImage(LirisiException):
    """Invalid key image."""


class IncorrectChecksum(LirisiException):
    """Incorrect checksum."""


class OIDHasherNotFound(LirisiException):
    """OID hasher not found."""


class OIDCurveNotFound(LirisiException):
    """OID curve not found."""


class UnsupportedCurveHashCombination(LirisiException):
    """Unsupported curve hash combination."""


class PointWasNotFound(LirisiException):
    """A point on the curve was not found. Please try another case identigier."""


class DecodePEMFailure(LirisiException):
    """Decode PEM failure."""


class UnexpectedRestOfSignature(LirisiException):
    """Unexpected rest at the end of signature."""


class Asn1MarshalFailed(LirisiException):
    """ASN1 Marshal failed."""


class PemEncodeFailed(LirisiException):
    """PEM Encode failed"""


class InvalidPointCoordinates(LirisiException):
    """Invalid point coordinates."""


class NilPointCoordinates(LirisiException):
    """Nil point coordinates."""


class ParseECPrivateKeyFailure(LirisiException):
    """Parse EC private key failed."""


class Asn1UnmarshalFailed(LirisiException):
    """ASN1 Unmarshal Failed."""


class MarshalPKIXPublicKeyFailed(LirisiException):
    """Marshal PKIX public key failed."""


class ParsePKIXPublicKeyFailed(LirisiException):
    """Parse PKIX public key failed."""


EXCEPTION_BY_STATUS = {
    1: PrivateKeyNotFitPublic,
    2: InsufficientNumberOfPublicKeys,
    3: PrivateKeyPositionOutOfRange,
    4: PrivateKeyNotFoundAmongPublicKeys,
    5: UnexpectedCurveType,
    6: UnexpectedHashType,
    7: IncorrectNumberOfSignatures,
    8: InvalidKeyImage,
    9: IncorrectChecksum,
    10: OIDHasherNotFound,
    11: OIDCurveNotFound,
    12: UnsupportedCurveHashCombination,
    13: PointWasNotFound,
    14: DecodePEMFailure,
    15: UnexpectedRestOfSignature,
    16: Asn1MarshalFailed,
    17: PemEncodeFailed,
    18: InvalidPointCoordinates,
    19: NilPointCoordinates,
    20: ParseECPrivateKeyFailure,
    21: Asn1UnmarshalFailed,
    22: MarshalPKIXPublicKeyFailed,
    23: ParsePKIXPublicKeyFailed,
}
