package ring

import (
	"crypto/elliptic"
	"encoding/asn1"
	"reflect"

	"hash"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/keybase/go-crypto/brainpool"
	"golang.org/x/crypto/sha3"
)

// Signature is struct with signature data.
// ## Serialize to DER
// ```
// PointData DEFINITIONS ::= BEGIN
// 		X := INTEGER
// 		Y := INTEGER
// END
//
// Signature DEFINITIONS ::= BEGIN
//     Name       ::= OCTET STRING,
//     Version    ::= INTEGER,
//     CurveOID   ::= OBJECT IDENTIFIER,
//     HashOID    ::= OBJECT IDENTIFIER,
//     KeyImage   ::= PointData,
//     Checksum   ::= INTEGER,
//     Signatures ::= SEQUENCE OF INTEGER
// END
// ```
// openssl asn1parse -i -dump -in signature.pem

// PointData holds X,Y coordinates of point.
// https://tools.ietf.org/html/rfc5480#section-2.2
// ECPoint ::= OCTET STRING
type PointData struct {
	X []byte
	Y []byte
}

// Signature holds data of ring signature.
type Signature struct {
	Name       string
	Version    int
	CurveOID   asn1.ObjectIdentifier
	HasherOID  asn1.ObjectIdentifier
	KeyImage   PointData
	Checksum   []byte
	Signatures [][]byte
}

// FoldedPublicKeys holds data of points of public keys.
type FoldedPublicKeys struct {
	Name      string
	CurveOID  asn1.ObjectIdentifier
	HasherOID asn1.ObjectIdentifier
	Digest    []byte
	Keys      [][]byte
}

// CurveCodes maps curve names to curves available to make signature.
var CurveCodes = map[string]func() elliptic.Curve{
	"secp224r1":  elliptic.P224, // NIST/SECG curve over a 224 bit prime field
	"prime256v1": elliptic.P256, // X9.62/SECG curve over a 256 bit prime field
	"secp384r1":  elliptic.P384, // NIST/SECG curve over a 384 bit prime field
	"secp521r1":  elliptic.P521, // NIST/SECG curve over a 521 bit prime field
	// x509.ParsePKIXPublicKey: unsupported elliptic curve
	"brainpoolP256r1": brainpool.P256r1, // RFC 5639 curve over a 256 bit prime field
	"brainpoolP256t1": brainpool.P256t1, // RFC 5639 curve over a 256 bit prime field
	"brainpoolP384r1": brainpool.P384r1, // RFC 5639 curve over a 384 bit prime field
	"brainpoolP384t1": brainpool.P384t1, // RFC 5639 curve over a 384 bit prime field
	"brainpoolP512r1": brainpool.P512r1, // RFC 5639 curve over a 512 bit prime field
	"brainpoolP512t1": brainpool.P512t1, // RFC 5639 curve over a 512 bit prime field
	"secp256k1":       crypto.S256,      // SECG curve over a 256 bit prime field
}

// HashCodes maps hash names to hash functions available to make signature.
// printf "test" | openssl dgst -sha3-256
var HashCodes = map[string]func() hash.Hash{
	"sha3-224": sha3.New224,
	"sha3-256": sha3.New256,
	"sha3-384": sha3.New384,
	"sha3-512": sha3.New512,
}

// Lirisi application version.
const LirisiVersion = "0.0.1"

// Status codes for sign/verify functions.
const (
	Origin                            = "github.com/zbohm/lirisi"
	SignatureVersion                  = 1
	Success                           = 0
	PrivateKeyNotFitPublic            = 1
	InsufficientNumberOfPublicKeys    = 2
	PrivateKeyPositionOutOfRange      = 3
	PrivateKeyNotFoundAmongPublicKeys = 4
	UnexpectedCurveType               = 5
	UnexpectedHashType                = 6
	IncorrectNumberOfSignatures       = 7
	InvalidKeyImage                   = 8
	IncorrectChecksum                 = 9
	OIDHasherNotFound                 = 10
	OIDCurveNotFound                  = 11
	UnsupportedCurveHashCombination   = 12
	PointWasNotFound                  = 13
	DecodePEMFailure                  = 14
	UnexpectedRestOfSignature         = 15
	Asn1MarshalFailed                 = 16
	EncodePEMFailed                   = 17
	InvalidPointCoordinates           = 18
	NilPointCoordinates               = 19
	ParseECPrivateKeyFailure          = 20
	Asn1UnmarshalFailed               = 21
	MarshalPKIXPublicKeyFailed        = 22
	ParsePKIXPublicKeyFailed          = 23
	CreateKeyFailed                   = 24
	MarshalKeyFailed                  = 25
)

// ErrorMessages convert status codes to human readable error messages.
var ErrorMessages = map[int]string{
	PrivateKeyNotFitPublic:            "Private key not fit public.",
	InsufficientNumberOfPublicKeys:    "Insufficient number of public keys.",
	PrivateKeyPositionOutOfRange:      "Private key position out of range.",
	PrivateKeyNotFoundAmongPublicKeys: "Private key not found among public keys.",
	UnexpectedCurveType:               "Unexpected curve type.",
	UnexpectedHashType:                "Unexpected hash type.",
	IncorrectNumberOfSignatures:       "Incorrect number of signatures.",
	InvalidKeyImage:                   "Invalid key image.",
	IncorrectChecksum:                 "Incorrect checksum.",
	OIDHasherNotFound:                 "OID hasher not found.",
	OIDCurveNotFound:                  "OID curve not found.",
	UnsupportedCurveHashCombination:   "Unsupported curve hash combination.",
	PointWasNotFound:                  "A point on the curve was not found. Please try another case identigier.",
	DecodePEMFailure:                  "Decode PEM failed.",
	UnexpectedRestOfSignature:         "Unexpected rest at the end of signature.",
	Asn1MarshalFailed:                 "ASN1 Marshal failed.",
	EncodePEMFailed:                   "PEM Encode failed.",
	InvalidPointCoordinates:           "Invalid point coordinates.",
	NilPointCoordinates:               "Nil point coordinates.",
	ParseECPrivateKeyFailure:          "Parse EC private key failed.",
	Asn1UnmarshalFailed:               "ASN1 Unmarshal Failed.",
	MarshalPKIXPublicKeyFailed:        "Marshal PKIX public key falied.",
	ParsePKIXPublicKeyFailed:          "Parse PKIX public key falied.",
	CreateKeyFailed:                   "Create key failed.",
	MarshalKeyFailed:                  "Marshal key failed.",
}

// GetCurveName returns curve name of the curve instace.
func GetCurveName(curve elliptic.Curve) string {
	for name, fncCurve := range CurveCodes {
		if fncCurve() == curve {
			return name
		}
	}
	return ""
}

// GetHasherName returns name of hash function.
func GetHasherName(fnc func() hash.Hash) string {
	refFnc := reflect.ValueOf(fnc)
	for name, fncHash := range HashCodes {
		if reflect.ValueOf(fncHash) == refFnc {
			return name
		}
	}
	return ""
}
