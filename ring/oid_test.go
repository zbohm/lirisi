package ring

import (
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/hex"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/keybase/go-crypto/brainpool"
	"golang.org/x/crypto/sha3"
	"hash"
	"testing"
)

func hashMessage(hasher func() hash.Hash, data []byte) []byte {
	h := hasher()
	if _, err := h.Write(data); err != nil {
		panic(err)
	}
	return h.Sum(nil)
}

func assertHasher(t *testing.T, oid asn1.ObjectIdentifier, digest string) {
	hasher, ok := GetHasher(oid)
	if !ok {
		t.Error("Unknown OID.")
	}
	if hex.EncodeToString(hashMessage(hasher, message)) != digest {
		t.Error("Unexpected digest.")
	}
}

func TestInvlaidHashOID(t *testing.T) {
	_, ok := GetHasher(asn1.ObjectIdentifier{0, 0, 0})
	if ok {
		t.Error("Unexpected OID.")
	}
}

func TestCreateOID(t *testing.T) {
	t.Parallel()
	if CreateOID("2.16.840.1.101.3.4.2.7").String() != "2.16.840.1.101.3.4.2.7" {
		t.Error("CreateOID failed.")
	}
}

func TestGetHasherNew224(t *testing.T) {
	t.Parallel()
	assertHasher(t,
		asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 7},
		"41e037bec99e456b7e4918b946814980a92cd35c78d4116ec62b2743")
}

func TestGetHasherNew256(t *testing.T) {
	t.Parallel()
	assertHasher(t,
		asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 8},
		"0bb1d52b3aa34f7099a538377275c3fbbfaf7c6fb4de78f94f2936d8cbde5309")
}

func TestGetHasherNew384(t *testing.T) {
	t.Parallel()
	assertHasher(t,
		asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 9},
		"3344ba0e3f5481d12a1c269b48baca213d852bf78f1bc6009680b9668abe2d6abab0c8239ffba2857c4ca694d878d505")
}

func TestGetHasherNew512(t *testing.T) {
	t.Parallel()
	assertHasher(t,
		asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 10},
		"5c43243687aa247a7969da7c9ff66dd1591fad82a22cd9fa3a579649a24fbb9a82201cb3c16fc5b855c8737948ffcf381455ec84b787"+
			"9609268b841bb22d06f7")
}

func assertCurve(t *testing.T, oid asn1.ObjectIdentifier, name string) {
	curveType, ok := GetCurve(oid)
	if !ok {
		t.Error("Unknown OID.")
	}
	curve := curveType()
	params := curve.Params()
	if params.Name != name {
		t.Error("Invalid curve type.")
	}
}

func TestInvlaidCurveOID(t *testing.T) {
	_, ok := GetCurve(asn1.ObjectIdentifier{0, 0, 0})
	if ok {
		t.Error("Unexpected OID.")
	}
}

func TestGetCurveP224(t *testing.T) {
	t.Parallel()
	assertCurve(t, asn1.ObjectIdentifier{1, 3, 132, 0, 33}, "P-224")
}

func TestGetCurveP256(t *testing.T) {
	t.Parallel()
	assertCurve(t, asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}, "P-256")
}

func TestGetCurveP384(t *testing.T) {
	t.Parallel()
	assertCurve(t, asn1.ObjectIdentifier{1, 3, 132, 0, 34}, "P-384")
}

func TestGetCurveP521(t *testing.T) {
	t.Parallel()
	assertCurve(t, asn1.ObjectIdentifier{1, 3, 132, 0, 35}, "P-521")
}

func TestGetCurveP256r1(t *testing.T) {
	t.Parallel()
	assertCurve(t, asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 7}, "brainpoolP256r1")
}

func TestGetCurveP256t1(t *testing.T) {
	t.Parallel()
	assertCurve(t, asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 8}, "brainpoolP256t1")
}

func TestGetCurveP384r1(t *testing.T) {
	t.Parallel()
	assertCurve(t, asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 11}, "brainpoolP384r1")
}

func TestGetCurveP384t1(t *testing.T) {
	t.Parallel()
	assertCurve(t, asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 12}, "brainpoolP384t1")
}

func TestGetCurveP512r1(t *testing.T) {
	t.Parallel()
	assertCurve(t, asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 13}, "brainpoolP512r1")
}

func TestGetCurveP512t1(t *testing.T) {
	t.Parallel()
	assertCurve(t, asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 14}, "brainpoolP512t1")
}

func TestGetCurveS256(t *testing.T) {
	t.Parallel()
	assertCurve(t, asn1.ObjectIdentifier{1, 3, 132, 0, 10}, "")
}

func TestGetHasherOIDNew224(t *testing.T) {
	oid, status := GetHasherOID(sha3.New224)
	if oid.String() != "2.16.840.1.101.3.4.2.7" {
		t.Error("OID does not match.")
	}
	if status != Success {
		t.Error(status)
	}
}

func TestGetHasherOIDNew256(t *testing.T) {
	oid, status := GetHasherOID(sha3.New256)
	if oid.String() != "2.16.840.1.101.3.4.2.8" {
		t.Error("OID does not match.")
	}
	if status != Success {
		t.Error(status)
	}
}

func TestGetHasherOIDNew384(t *testing.T) {
	oid, status := GetHasherOID(sha3.New384)
	if oid.String() != "2.16.840.1.101.3.4.2.9" {
		t.Error("OID does not match.")
	}
	if status != Success {
		t.Error(status)
	}
}

func TestGetHasherOIDNew512(t *testing.T) {
	oid, status := GetHasherOID(sha3.New512)
	if oid.String() != "2.16.840.1.101.3.4.2.10" {
		t.Error("OID does not match.")
	}
	if status != Success {
		t.Error(status)
	}
}

func TestGetCurveOIDP224(t *testing.T) {
	oid, status := GetCurveOID(elliptic.P224)
	if oid.String() != "1.3.132.0.33" {
		t.Error("OID does not match.")
	}
	if status != Success {
		t.Error(status)
	}
}

func TestGetCurveOIDP256(t *testing.T) {
	oid, status := GetCurveOID(elliptic.P256)
	if oid.String() != "1.2.840.10045.3.1.7" {
		t.Error("OID does not match.")
	}
	if status != Success {
		t.Error(status)
	}
}

func TestGetCurveOIDP384(t *testing.T) {
	oid, status := GetCurveOID(elliptic.P384)
	if oid.String() != "1.3.132.0.34" {
		t.Error("OID does not match.")
	}
	if status != Success {
		t.Error(status)
	}
}

func TestGetCurveOIDP521(t *testing.T) {
	oid, status := GetCurveOID(elliptic.P521)
	if oid.String() != "1.3.132.0.35" {
		t.Error("OID does not match.")
	}
	if status != Success {
		t.Error(status)
	}
}

func TestGetCurveOIDP256r1(t *testing.T) {
	oid, status := GetCurveOID(brainpool.P256r1)
	if oid.String() != "1.3.36.3.3.2.8.1.1.7" {
		t.Error("OID does not match.")
	}
	if status != Success {
		t.Error(status)
	}
}

func TestGetCurveOIDP256t1(t *testing.T) {
	oid, status := GetCurveOID(brainpool.P256t1)
	if oid.String() != "1.3.36.3.3.2.8.1.1.8" {
		t.Error("OID does not match.")
	}
	if status != Success {
		t.Error(status)
	}
}

func TestGetCurveOIDP384r1(t *testing.T) {
	oid, status := GetCurveOID(brainpool.P384r1)
	if oid.String() != "1.3.36.3.3.2.8.1.1.11" {
		t.Error("OID does not match.")
	}
	if status != Success {
		t.Error(status)
	}
}

func TestGetCurveOIDP384t1(t *testing.T) {
	oid, status := GetCurveOID(brainpool.P384t1)
	if oid.String() != "1.3.36.3.3.2.8.1.1.12" {
		t.Error("OID does not match.")
	}
	if status != Success {
		t.Error(status)
	}
}

func TestGetCurveOIDP512r1(t *testing.T) {
	oid, status := GetCurveOID(brainpool.P512r1)
	if oid.String() != "1.3.36.3.3.2.8.1.1.13" {
		t.Error("OID does not match.")
	}
	if status != Success {
		t.Error(status)
	}
}

func TestGetCurveOIDP512t1(t *testing.T) {
	oid, status := GetCurveOID(brainpool.P512t1)
	if oid.String() != "1.3.36.3.3.2.8.1.1.14" {
		t.Error("OID does not match.")
	}
	if status != Success {
		t.Error(status)
	}
}

func TestGetCurveOIDS256(t *testing.T) {
	oid, status := GetCurveOID(crypto.S256)
	if oid.String() != "1.3.132.0.10" {
		t.Error("OID does not match.")
	}
	if status != Success {
		t.Error(status)
	}
}
