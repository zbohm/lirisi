package ring

import (
	"crypto/elliptic"
	"encoding/asn1"
	"hash"
	"reflect"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/keybase/go-crypto/brainpool"
	"golang.org/x/crypto/sha3"
)

// http://oidref.com/$OID

// OIDHashers - Object identifier standardized by ITU.
var OIDHashers = map[string]func() hash.Hash{
	"2.16.840.1.101.3.4.2.7":  sha3.New224,
	"2.16.840.1.101.3.4.2.8":  sha3.New256,
	"2.16.840.1.101.3.4.2.9":  sha3.New384,
	"2.16.840.1.101.3.4.2.10": sha3.New512,
}

// OIDCurves - Object identifier standardized by ITU.
var OIDCurves = map[string]func() elliptic.Curve{
	"1.3.132.0.33":          elliptic.P224,    // secp224r1 : NIST/SECG curve over a 224 bit prime field
	"1.2.840.10045.3.1.7":   elliptic.P256,    // prime256v1 (secp256r1): X9.62/SECG curve over a 256 bit prime field
	"1.3.132.0.34":          elliptic.P384,    // secp384r1 : NIST/SECG curve over a 384 bit prime field
	"1.3.132.0.35":          elliptic.P521,    // secp521r1 : NIST/SECG curve over a 521 bit prime field
	"1.3.36.3.3.2.8.1.1.7":  brainpool.P256r1, // brainpoolP256r1: RFC 5639 curve over a 256 bit prime field
	"1.3.36.3.3.2.8.1.1.8":  brainpool.P256t1, // brainpoolP256t1: RFC 5639 curve over a 256 bit prime field
	"1.3.36.3.3.2.8.1.1.11": brainpool.P384r1, // brainpoolP384r1: RFC 5639 curve over a 384 bit prime field
	"1.3.36.3.3.2.8.1.1.12": brainpool.P384t1, // brainpoolP384t1: RFC 5639 curve over a 384 bit prime field
	"1.3.36.3.3.2.8.1.1.13": brainpool.P512r1, // brainpoolP512r1: RFC 5639 curve over a 512 bit prime field
	"1.3.36.3.3.2.8.1.1.14": brainpool.P512t1, // brainpoolP512t1: RFC 5639 curve over a 512 bit prime field
	"1.3.132.0.10":          crypto.S256,      // secp256k1 : SECG curve over a 256 bit prime field
}

// GetHasher returns hash function and error.
func GetHasher(oid asn1.ObjectIdentifier) (func() hash.Hash, bool) {
	fnc, ok := OIDHashers[oid.String()]
	return fnc, ok
}

// GetCurve returns hash function and error.
func GetCurve(oid asn1.ObjectIdentifier) (func() elliptic.Curve, bool) {
	curve, ok := OIDCurves[oid.String()]
	return curve, ok
}

// CreateOID creates asn1.ObjectIdentifier
func CreateOID(s string) asn1.ObjectIdentifier {
	numbers := strings.Split(s, ".")
	oid := make(asn1.ObjectIdentifier, len(numbers))
	for i, s := range numbers {
		n, err := strconv.Atoi(s)
		if err != nil {
			panic(err)
		}
		oid[i] = n
	}
	return oid
}

// GetHasherOID return OID of hash function.
func GetHasherOID(fnc func() hash.Hash) (asn1.ObjectIdentifier, int) {
	refFnc := reflect.ValueOf(fnc)
	for key, value := range OIDHashers {
		if reflect.ValueOf(value) == refFnc {
			return CreateOID(key), Success
		}
	}
	return asn1.ObjectIdentifier{}, OIDHasherNotFound
}

// GetCurveOID return OID of elliptic curve.
func GetCurveOID(curve func() elliptic.Curve) (asn1.ObjectIdentifier, int) {
	refFnc := reflect.ValueOf(curve)
	for key, value := range OIDCurves {
		if reflect.ValueOf(value) == refFnc {
			return CreateOID(key), Success
		}
	}
	return asn1.ObjectIdentifier{}, OIDCurveNotFound
}

// GetCurveOIDForCurve return OID of elliptic curve instance.
func GetCurveOIDForCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, int) {
	for key, fncCurve := range OIDCurves {
		if fncCurve() == curve {
			return CreateOID(key), Success
		}
	}
	return asn1.ObjectIdentifier{}, OIDCurveNotFound
}
