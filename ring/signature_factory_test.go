package ring

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"hash"
	"math/big"
	mathRand "math/rand"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/keybase/go-crypto/brainpool"
	"golang.org/x/crypto/sha3"
)

var message = []byte(`What is answer to life the universe and everything?`)

var _ = fmt.Println
var skipFixed = false // Skip tests with fixed values. Fixed means that all random values are deterministic.

var hashers = []func() hash.Hash{sha3.New224, sha3.New256, sha3.New384, sha3.New512}
var curves = []func() elliptic.Curve{
	elliptic.P224,
	elliptic.P256,
	elliptic.P384,
	elliptic.P521,
	brainpool.P256r1,
	brainpool.P256t1,
	brainpool.P384r1,
	brainpool.P384t1,
	brainpool.P512r1,
	brainpool.P512t1,
}

// ScalarBaseMult can't handle scalars > 256 bits
// https://github.com/ethereum/go-ethereum/blob/v1.9.25/crypto/secp256k1/curve.go#L249
var biggerHashers = []func() hash.Hash{sha3.New384, sha3.New512}
var hashers32 = []func() hash.Hash{sha3.New224, sha3.New256}
var curves32 = []func() elliptic.Curve{crypto.S256}

func testAllCurvesAndHashers(
	t *testing.T,
	fncTest func(t *testing.T, curve func() elliptic.Curve, hasher func() hash.Hash, size int, priv int),
) {
	for _, curve := range curves {
		for _, hasher := range hashers {
			fncTest(t, curve, hasher, 3, 2)
		}
	}
	for _, curve := range curves32 {
		for _, hasher := range hashers32 {
			fncTest(t, curve, hasher, 3, 2)
		}
	}
}

func createPrivatePublicKeys(curveType func() elliptic.Curve, size int) ([]*ecdsa.PrivateKey, []*ecdsa.PublicKey) {
	privateKeys := make([]*ecdsa.PrivateKey, size)
	publicKeys := make([]*ecdsa.PublicKey, size)
	curve := curveType()
	for i := 0; i < size; i++ {
		privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			panic(err)
		}
		privateKeys[i] = privKey
		publicKeys[i] = &privKey.PublicKey
	}
	return privateKeys, publicKeys
}

func TestMakeSignature(t *testing.T) {
	if skipFixed {
		t.Skip("Skip test with fixed values.")
	}
	rand.Reader = mathRand.New(mathRand.NewSource(42))
	curve := elliptic.P256
	privateKeys, publicKeys := createPrivatePublicKeys(curve, 10)
	caseIdentifier := []byte(``)
	status, sign := MakeSignature(curve, sha3.New256, privateKeys[2], publicKeys, 2, message, caseIdentifier)
	if status != Success {
		t.Error(status)
	}
	if sign == nil {
		t.Fatal("Signature is nil.")
	}
	if Verify(sign, publicKeys, message, caseIdentifier) != Success {
		t.Error("Signature is not valid.")
	}
	// // Dump signature
	// fmt.Printf("X: \"%x\"\n", sign.KeyImage.X)
	// fmt.Printf("Y: \"%x\"\n", sign.KeyImage.Y)
	// fmt.Printf("C: \"%x\"\n", sign.Checksum)
	// for _, value := range sign.Signatures {
	// 	fmt.Printf("\"%s\",\n", hex.EncodeToString(value))
	// }
	if hex.EncodeToString(sign.KeyImage.X) != "60fa109699e9a43ff6bd1f01dd74a90475b97ec7d250926378cddca3b27a8af0" {
		t.Error("Key image X doesn't not match.")
	}
	if hex.EncodeToString(sign.KeyImage.Y) != "3243b59391495b2b3d922f2dfc922724eefeef4c37731d7c4670e75a4841af19" {
		t.Error("Key image X doesn't not match.")
	}
	if hex.EncodeToString(sign.Checksum) != "8bf11f1a5405eb3b2c118645012d69d33c82091940df95bbc3be8a0f11c4e629" {
		t.Error("Key image X doesn't not match.")
	}
	signatures := []string{
		"a916585e183bb709192db0e6c8d709b9d7383b993c69499945b0b0cfe3dc2ec1",
		"fc9610d7eeb19d0916a27423c29e442f0e31c2c9539660f05fb37e45cd1bf0bc",
		"494036a7c595db8e8f03a5e6f8a3cc862fa5f372638831279b2d8c87bf3f108c",
		"b8aa047c61cdb33373ebe72c27a098c02197dae6b732c351df668f874e2c9f1c",
		"e09ca86017e7e21748303ff41c1b23e11c48ed17539d685f76f2a798bc64de0e",
		"5db2864b2ad3c26ce6382342765a13d696e52df760f6c3465e29a0dca46ac3a0",
		"d570133bc21571f5f54a643105513fd8429b194ae1ba9f2a8386ae72b3661fe8",
		"2c2ac64dbf46151824e2305312637c99c2b87d6df0dd5ef2836719072d672f61",
		"faa0be86f457921ec37c0e460cf0d703d07dc5f5661a450133409a712b6a66ab",
		"d7ba65224ca26978d9a5ce62feb11a838f16622eb54cee3e6755229c183c1933",
	}
	for i, value := range sign.Signatures {
		if hex.EncodeToString(value) != signatures[i] {
			t.Errorf("Signature[%d] doesn't not match.", i)
		}
	}
}

// Convert hexstring to array of bytes.
func h2b(t *testing.T, s string) []byte {
	buff, err := hex.DecodeString(s)
	if err != nil {
		t.Error(err)
	}
	return buff
}

func getSignature(t *testing.T, curve func() elliptic.Curve) *Signature {
	curveOid, _ := GetCurveOID(curve)
	return &Signature{
		CurveOID:  curveOid,
		HasherOID: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 8}, // sha3.New256
		KeyImage: PointData{
			h2b(t, "60fa109699e9a43ff6bd1f01dd74a90475b97ec7d250926378cddca3b27a8af0"),
			h2b(t, "3243b59391495b2b3d922f2dfc922724eefeef4c37731d7c4670e75a4841af19"),
		},
		Checksum: h2b(t, "8bf11f1a5405eb3b2c118645012d69d33c82091940df95bbc3be8a0f11c4e629"),
		Signatures: [][]byte{
			h2b(t, "a916585e183bb709192db0e6c8d709b9d7383b993c69499945b0b0cfe3dc2ec1"),
			h2b(t, "fc9610d7eeb19d0916a27423c29e442f0e31c2c9539660f05fb37e45cd1bf0bc"),
			h2b(t, "494036a7c595db8e8f03a5e6f8a3cc862fa5f372638831279b2d8c87bf3f108c"),
			h2b(t, "b8aa047c61cdb33373ebe72c27a098c02197dae6b732c351df668f874e2c9f1c"),
			h2b(t, "e09ca86017e7e21748303ff41c1b23e11c48ed17539d685f76f2a798bc64de0e"),
			h2b(t, "5db2864b2ad3c26ce6382342765a13d696e52df760f6c3465e29a0dca46ac3a0"),
			h2b(t, "d570133bc21571f5f54a643105513fd8429b194ae1ba9f2a8386ae72b3661fe8"),
			h2b(t, "2c2ac64dbf46151824e2305312637c99c2b87d6df0dd5ef2836719072d672f61"),
			h2b(t, "faa0be86f457921ec37c0e460cf0d703d07dc5f5661a450133409a712b6a66ab"),
			h2b(t, "d7ba65224ca26978d9a5ce62feb11a838f16622eb54cee3e6755229c183c1933"),
		},
	}
}

func TestVerifySignature(t *testing.T) {
	if skipFixed {
		t.Skip("Skip test with fixed values.")
	}
	rand.Reader = mathRand.New(mathRand.NewSource(42))
	curve := elliptic.P256
	_, publicKeys := createPrivatePublicKeys(curve, 10)
	caseIdentifier := []byte(``)

	sign := getSignature(t, curve)
	if Verify(sign, publicKeys, message, caseIdentifier) != Success {
		t.Error("Signature is not valid.")
	}
}

func TestKeyImageEquals(t *testing.T) {
	t.Parallel()
	testAllCurvesAndHashers(t, func(t *testing.T, curve func() elliptic.Curve, hasher func() hash.Hash, size int, priv int) {
		privateKeys, publicKeys := createPrivatePublicKeys(curve, size)
		caseIdentifier := []byte(``)
		status1, sign1 := Create(curve, hasher, privateKeys[priv], publicKeys, message, caseIdentifier)
		if status1 != Success {
			t.Error(status1)
		}
		status2, sign2 := Create(curve, hasher, privateKeys[priv], publicKeys, message, caseIdentifier)
		if status2 != Success {
			t.Error(status2)
		}
		if !bytes.Equal(sign1.KeyImage.X, sign2.KeyImage.X) {
			t.Error("Key images X/X doesn't not equal.")
		}
		if !bytes.Equal(sign1.KeyImage.Y, sign2.KeyImage.Y) {
			t.Error("Key images Y/Y doesn't not equal.")
		}
	})
}

func TestKeyImageDifferentMessage(t *testing.T) {
	t.Parallel()
	testAllCurvesAndHashers(t, func(t *testing.T, curve func() elliptic.Curve, hasher func() hash.Hash, size int, priv int) {
		privateKeys, publicKeys := createPrivatePublicKeys(curve, size)
		caseIdentifier := []byte(``)
		status1, sign1 := Create(curve, hasher, privateKeys[priv], publicKeys, message, caseIdentifier)
		if status1 != Success {
			t.Error(status1)
		}
		msg := append(message, []byte(`!`)...)
		status2, sign2 := Create(curve, hasher, privateKeys[priv], publicKeys, msg, caseIdentifier)
		if status2 != Success {
			t.Error(status2)
		}
		if !bytes.Equal(sign1.KeyImage.X, sign2.KeyImage.X) {
			t.Error("Key images X/X doesn't not equal.")
		}
		if !bytes.Equal(sign1.KeyImage.Y, sign2.KeyImage.Y) {
			t.Error("Key images Y/Y doesn't not equal.")
		}
	})
}

func TestKeyImageDifferentOrderPublicKeys(t *testing.T) {
	t.Parallel()
	testAllCurvesAndHashers(t, func(t *testing.T, curve func() elliptic.Curve, hasher func() hash.Hash, size int, priv int) {
		privateKeys, publicKeys := createPrivatePublicKeys(curve, size)
		caseIdentifier := []byte(``)
		status1, sign1 := Create(curve, hasher, privateKeys[priv], publicKeys, message, caseIdentifier)
		if status1 != Success {
			t.Error(status1)
		}
		publicKeys[0], publicKeys[1] = publicKeys[1], publicKeys[0]
		status2, sign2 := Create(curve, hasher, privateKeys[priv], publicKeys, message, caseIdentifier)
		if status2 != Success {
			t.Error(status2)
		}
		if bytes.Equal(sign1.KeyImage.X, sign2.KeyImage.X) {
			t.Error("Key images X/X equals.")
		}
		if bytes.Equal(sign1.KeyImage.Y, sign2.KeyImage.Y) {
			t.Error("Key images Y/Y equals.")
		}
	})
}

func TestKeyImageDifferentCase(t *testing.T) {
	t.Parallel()
	testAllCurvesAndHashers(t, func(t *testing.T, curve func() elliptic.Curve, hasher func() hash.Hash, size int, priv int) {
		privateKeys, publicKeys := createPrivatePublicKeys(curve, size)
		status1, sign1 := Create(curve, hasher, privateKeys[priv], publicKeys, message, []byte(``))
		if status1 != Success {
			t.Error(status1)
		}
		status2, sign2 := Create(curve, hasher, privateKeys[priv], publicKeys, message, []byte(`!`))
		if status2 != Success {
			t.Error(status2)
		}
		if bytes.Equal(sign1.KeyImage.X, sign2.KeyImage.X) {
			t.Error("Key images X/X equals.")
		}
		if bytes.Equal(sign1.KeyImage.Y, sign2.KeyImage.Y) {
			t.Error("Key images Y/Y equals.")
		}
	})
}

// Unique Ring Signatures (URS) - broken cryptography
// https://kewde.github.io/urs
func TestKeyImageExploit(t *testing.T) {
	t.Parallel()
	curve := elliptic.P256
	privateKeys, publicKeys := createPrivatePublicKeys(curve, 5)

	caseIdentifier := []byte(``)
	status, sign := Create(curve, sha3.New256, privateKeys[3], publicKeys, message, caseIdentifier)
	if status != Success {
		t.Error(status)
	}
	keyImage := Point{BuffToInt(sign.KeyImage.X), BuffToInt(sign.KeyImage.Y)}
	L := ConvertPublicKeysToPoints(publicKeys)
	buff := append(PointsToBytes(L), caseIdentifier...)
	fc := FactoryContext{Curve: curve(), Hasher: sha3.New256}
	digest := fc.MakeDigest(buff)

	for i, pub := range publicKeys {
		rx, ry := fc.Curve.ScalarMult(pub.X, pub.Y, digest)
		if keyImage.x.Cmp(rx) == 0 && keyImage.y.Cmp(ry) == 0 {
			t.Errorf("Exploit! Found public key: %d\n", i)
		}
	}
}

func TestKeyImageExploit2(t *testing.T) {
	t.Parallel()
	curve := elliptic.P256
	privateKeys, publicKeys := createPrivatePublicKeys(curve, 5)

	caseIdentifier := []byte(``)
	status, sign := Create(curve, sha3.New256, privateKeys[3], publicKeys, message, caseIdentifier)
	if status != Success {
		t.Error(status)
	}
	keyImage := Point{BuffToInt(sign.KeyImage.X), BuffToInt(sign.KeyImage.Y)}
	L := ConvertPublicKeysToPoints(publicKeys)

	buff1 := append(PointsToBytes(L), caseIdentifier...)
	buff2 := make([]byte, len(buff1))
	for i, j := 0, len(buff1)-1; i < len(buff1); i, j = i+1, j-1 {
		buff2[i] = buff1[j]
	}
	fc := FactoryContext{Curve: curve(), Hasher: sha3.New256}
	digest1 := fc.MakeDigest(buff1)
	digest2 := fc.MakeDigest(buff2)

	x1, y1 := fc.Curve.ScalarBaseMult(digest1)
	x2, y2 := fc.Curve.ScalarBaseMult(digest2)
	x, y := fc.Curve.Add(x1, y1, x2, y2)

	for i, pub := range publicKeys {
		assertCoordinatesRXY(t, fc, keyImage, pub, digest1, digest2, x, y, x1, y1, x2, y2, i)
		assertCoordinatesSXY(t, fc, keyImage, pub, digest1, digest2, x, y, x1, y1, x2, y2, i)
	}
}

func assertCoordinatesRXY(
	t *testing.T,
	fc FactoryContext,
	keyImage Point,
	pub *ecdsa.PublicKey,
	digest1, digest2 []byte,
	x, y, x1, y1, x2, y2 *big.Int,
	i int,
) {
	rx, ry := fc.Curve.ScalarMult(pub.X, pub.Y, digest1)
	if keyImage.x.Cmp(rx) == 0 && keyImage.y.Cmp(ry) == 0 {
		t.Errorf("1. Exploit! Found public key: %d\n", i)
	}
	rx, ry = fc.Curve.ScalarMult(pub.X, pub.Y, digest2)
	if keyImage.x.Cmp(rx) == 0 && keyImage.y.Cmp(ry) == 0 {
		t.Errorf("2. Exploit! Found public key: %d\n", i)
	}
	if keyImage.x.Cmp(x1) == 0 && keyImage.y.Cmp(y1) == 0 {
		t.Errorf("3. Exploit! Found public key: %d\n", i)
	}
	if keyImage.x.Cmp(x2) == 0 && keyImage.y.Cmp(y2) == 0 {
		t.Errorf("4. Exploit! Found public key: %d\n", i)
	}
	if keyImage.x.Cmp(x) == 0 && keyImage.y.Cmp(y) == 0 {
		t.Errorf("5. Exploit! Found public key: %d\n", i)
	}
}

func assertCoordinatesSXY(
	t *testing.T,
	fc FactoryContext,
	keyImage Point,
	pub *ecdsa.PublicKey,
	digest1, digest2 []byte,
	x, y, x1, y1, x2, y2 *big.Int,
	i int,
) {
	sx, sy := fc.Curve.Add(pub.X, pub.Y, pub.X, pub.Y)
	if x1.Cmp(sx) == 0 && y1.Cmp(sy) == 0 {
		t.Errorf("6. Exploit! Found public key: %d\n", i)
	}
	if x2.Cmp(sx) == 0 && y2.Cmp(sy) == 0 {
		t.Errorf("7. Exploit! Found public key: %d\n", i)
	}
	if x.Cmp(sx) == 0 && y.Cmp(sy) == 0 {
		t.Errorf("8. Exploit! Found public key: %d\n", i)
	}
	if x1.Cmp(pub.X) == 0 && y1.Cmp(pub.Y) == 0 {
		t.Errorf("9. Exploit! Found public key: %d\n", i)
	}
	if x2.Cmp(pub.X) == 0 && y2.Cmp(pub.Y) == 0 {
		t.Errorf("10. Exploit! Found public key: %d\n", i)
	}
	if x.Cmp(pub.X) == 0 && y.Cmp(pub.Y) == 0 {
		t.Errorf("11. Exploit! Found public key: %d\n", i)
	}
}

func TestSignPrivateNotFitPublic(t *testing.T) {
	t.Parallel()
	curve := elliptic.P256
	privateKeys, publicKeys := createPrivatePublicKeys(curve, 3)
	status, sign := MakeSignature(curve, sha3.New256, privateKeys[1], publicKeys, 0, message, []byte(``))
	if sign != nil {
		t.Error("Error: Signature is not nil.")
	}
	if status != PrivateKeyNotFitPublic {
		t.Error("Error: 'public key does not fit private' was not risen.")
	}
}

func TestSignTooLowPrivateKeyPosition(t *testing.T) {
	t.Parallel()
	curve := elliptic.P256
	privateKeys, publicKeys := createPrivatePublicKeys(curve, 3)
	status, sign := MakeSignature(curve, sha3.New256, privateKeys[1], publicKeys, -1, message, []byte(``))
	if sign != nil {
		t.Error("Error: Signature is not nil.")
	}
	if status != PrivateKeyPositionOutOfRange {
		t.Error("Error: 'private key position out of range' was not risen.")
	}
}

func TestSignTooHighPrivateKeyPosition(t *testing.T) {
	t.Parallel()
	curve := elliptic.P256
	privateKeys, publicKeys := createPrivatePublicKeys(curve, 3)
	status, sign := MakeSignature(curve, sha3.New256, privateKeys[0], publicKeys, 3, message, []byte(``))
	if sign != nil {
		t.Error("Error: Signature is not nil.")
	}
	if status != PrivateKeyPositionOutOfRange {
		t.Error("Error: 'private key position out of range' was not risen.")
	}
}

func TestSignTooSmallRing(t *testing.T) {
	t.Parallel()
	curve := elliptic.P256
	privateKeys, publicKeys := createPrivatePublicKeys(curve, 1)
	status, sign := MakeSignature(curve, sha3.New256, privateKeys[0], publicKeys, 0, message, []byte(``))
	if sign != nil {
		t.Error("Error: Signature is not nil.")
	}
	if status != InsufficientNumberOfPublicKeys {
		t.Error("Error 'number of keys less than two' was not risen.")
	}
}

func TestSignUnexpectedCurveType(t *testing.T) {
	t.Parallel()
	curve1 := elliptic.P256
	curve2 := elliptic.P224
	privateKeys1, publicKeys1 := createPrivatePublicKeys(curve1, 3)
	_, publicKeys2 := createPrivatePublicKeys(curve2, 3)
	publicKeys1[2] = publicKeys2[2]
	status, sign := MakeSignature(curve1, sha3.New256, privateKeys1[0], publicKeys1, 0, message, []byte(``))
	if sign != nil {
		t.Error("Error: Signature is not nil.")
	}
	if status != UnexpectedCurveType {
		t.Error("Error 'unexpected curve type in public key[#]' was not risen.")
	}
}

func TestVerifyInvalidSignaturesLength(t *testing.T) {
	if skipFixed {
		t.Skip("Skip test with fixed values.")
	}
	rand.Reader = mathRand.New(mathRand.NewSource(42))
	curve := elliptic.P256
	_, publicKeys := createPrivatePublicKeys(curve, 9)
	sign := getSignature(t, curve)
	if Verify(sign, publicKeys, message, []byte(``)) == Success {
		t.Error("Invalid signature length doesn't rise error.")
	}
}

func TestVerifyUnexpectedCurveType(t *testing.T) {
	if skipFixed {
		t.Skip("Skip test with fixed values.")
	}
	rand.Reader = mathRand.New(mathRand.NewSource(42))
	curve := elliptic.P224
	_, publicKeys := createPrivatePublicKeys(curve, 10)
	sign := getSignature(t, curve)
	if Verify(sign, publicKeys, message, []byte(``)) == Success {
		t.Error("Unexpected curve type doesn't rise error.")
	}
}

func TestInvalidKeyImage(t *testing.T) {
	if skipFixed {
		t.Skip("Skip test with fixed values.")
	}
	rand.Reader = mathRand.New(mathRand.NewSource(42))
	curve := elliptic.P256
	_, publicKeys := createPrivatePublicKeys(curve, 10)
	sign := getSignature(t, curve)
	sign.KeyImage.X[0]++
	if Verify(sign, publicKeys, message, []byte(``)) == Success {
		t.Error("Invalid key image doesn't rise error.")
	}
}

func TestVerifyDifferentOrderOfPublicKeys(t *testing.T) {
	t.Parallel()
	testAllCurvesAndHashers(t, func(t *testing.T, curve func() elliptic.Curve, hasher func() hash.Hash, size int, priv int) {
		privateKeys, publicKeys := createPrivatePublicKeys(curve, size)
		caseIdentifier := []byte(``)
		status, sign := Create(curve, hasher, privateKeys[priv], publicKeys, message, caseIdentifier)
		if status != Success {
			t.Error(status)
		}
		publicKeys[0], publicKeys[1] = publicKeys[1], publicKeys[0]
		if Verify(sign, publicKeys, message, caseIdentifier) == Success {
			t.Error("Signature with different order of public keys was verified.")
		}
	})
}

func TestVerifyDifferentPublicKeys(t *testing.T) {
	t.Parallel()
	size := 10
	curve := elliptic.P256
	privateKeys, publicKeys := createPrivatePublicKeys(curve, size)
	caseIdentifier := []byte(``)
	status, sign := Create(curve, sha3.New256, privateKeys[2], publicKeys, message, caseIdentifier)
	if status != Success {
		t.Error(status)
	}
	_, publicKeys2 := createPrivatePublicKeys(curve, 1)
	publicKeys[8] = publicKeys2[0]
	if Verify(sign, publicKeys, message, caseIdentifier) == Success {
		t.Error("Signature with different public keys was verified.")
	}
}

func TestVerifyDifferentMessage(t *testing.T) {
	t.Parallel()
	size := 10
	curve := elliptic.P256
	privateKeys, publicKeys := createPrivatePublicKeys(curve, size)
	caseIdentifier := []byte(``)
	status, sign := Create(curve, sha3.New256, privateKeys[2], publicKeys, message, caseIdentifier)
	if status != Success {
		t.Error(status)
	}
	if Verify(sign, publicKeys, append(message, []byte(`!`)...), caseIdentifier) == Success {
		t.Error("Signature with different message was verified.")
	}
}

func TestVerifyDifferentCase(t *testing.T) {
	t.Parallel()
	size := 10
	curve := elliptic.P256
	privateKeys, publicKeys := createPrivatePublicKeys(curve, size)
	caseIdentifier := []byte(``)
	status, sign := Create(curve, sha3.New256, privateKeys[2], publicKeys, message, caseIdentifier)
	if status != Success {
		t.Error(status)
	}
	if Verify(sign, publicKeys, message, append(caseIdentifier, []byte(`!`)...)) == Success {
		t.Error("Signature with different message was verified.")
	}
}

func TestCurvesSignVerify(t *testing.T) {
	t.Parallel()
	testAllCurvesAndHashers(t, func(t *testing.T, curve func() elliptic.Curve, hasher func() hash.Hash, size int, priv int) {
		privateKeys, publicKeys := createPrivatePublicKeys(curve, size)
		caseIdentifier := []byte(``)
		status, sign := Create(curve, hasher, privateKeys[priv], publicKeys, message, caseIdentifier)
		if status != Success {
			t.Error(status)
		}
		if Verify(sign, publicKeys, message, caseIdentifier) != Success {
			t.Errorf("Signature is not valid for %v and %v.", curve(), hasher())
		}
	})
}

func TestSignCurveS256WithUnsupportedHashers(t *testing.T) {
	t.Parallel()
	curve := crypto.S256
	privateKeys, publicKeys := createPrivatePublicKeys(curve, 3)
	caseIdentifier := []byte(``)
	doTest := func(t *testing.T, curve func() elliptic.Curve, hasher func() hash.Hash) {
		status, sign := Create(curve, hasher, privateKeys[1], publicKeys, message, caseIdentifier)
		if status != UnsupportedCurveHashCombination {
			t.Error(status)
		}
		if sign != nil {
			t.Error("Signature is not nil.")
		}
	}
	for _, hasher := range biggerHashers {
		doTest(t, curve, hasher)
	}
}

func TestVerifyCurveS256WithUnsupportedHashers(t *testing.T) {
	t.Parallel()
	curve := elliptic.P256
	curveS256Oid, status := GetCurveOID(crypto.S256)
	if status != Success {
		t.Fatal("Invalid OID of crypto.S256.")
	}
	privateKeys, publicKeys := createPrivatePublicKeys(curve, 3)
	caseIdentifier := []byte(``)
	doTest := func(t *testing.T, curve func() elliptic.Curve, hasher func() hash.Hash) {
		status, sign := Create(curve, hasher, privateKeys[1], publicKeys, message, caseIdentifier)
		if status != Success {
			t.Error(status)
		}
		if sign == nil {
			t.Fatal("Signature is nil.")
		}
		sign.CurveOID = curveS256Oid
		if Verify(sign, publicKeys, message, caseIdentifier) != UnsupportedCurveHashCombination {
			t.Errorf("Signature is no raise UnsupportedCurveHashCombination for %v and %v.", curve(), hasher())
		}
	}
	for _, hasher := range biggerHashers {
		doTest(t, curve, hasher)
	}
}
