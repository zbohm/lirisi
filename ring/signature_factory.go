// # Ring signature factory.

// Note: To show as a literar code documentation compile this code by [gocco](https://github.com/nikhilm/gocco):
// ```
// $ gocco ring/signature_factory.go
// $ firefox docs/signature_factory.html
// ```

package ring

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"hash"
	"math/big"
	"reflect"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"
)

// FactoryContext holds curve object and hash function.
type FactoryContext struct {
	Curve  elliptic.Curve
	Hasher func() hash.Hash
}

// Point on elliptic curve.
type Point struct {
	x, y *big.Int
}

// Bytes returns bytess of Key image.
func (p PointData) Bytes() []byte {
	return append(p.X, p.Y...)
}

// Bytes returns bytess of Point.
func (p Point) Bytes() []byte {
	return append(p.x.Bytes(), p.y.Bytes()...)
}

// MakeDigest makes hash digest from data.
func (fc FactoryContext) MakeDigest(data []byte) []byte {
	h := fc.Hasher()
	if _, err := h.Write(data); err != nil {
		panic(err)
	}
	return h.Sum(nil)
}

// PointScalarMult provide scalar multiplication over elliptic curve.
func (fc FactoryContext) PointScalarMult(p Point, n []byte) Point {
	x, y := fc.Curve.ScalarMult(p.x, p.y, n)
	return Point{x, y}
}

// PointAdd provide add points over elliptic curve.
func (fc FactoryContext) PointAdd(p1, p2 Point) Point {
	if p1.x == nil {
		return p2
	}
	x, y := fc.Curve.Add(p1.x, p1.y, p2.x, p2.y)
	return Point{x, y}
}

func (fc FactoryContext) getSignatureDigest(
	publicKeysDigest []byte,
	privateImage Point,
	messageDigest []byte,
	gsiYici Point,
	hsiYci Point,
) []byte {
	buff := append(publicKeysDigest, privateImage.Bytes()...)
	buff = append(buff, gsiYici.Bytes()...)
	buff = append(buff, hsiYci.Bytes()...)
	buff = append(buff, messageDigest...)
	return fc.MakeDigest(buff)
}

// HashPublicKeysIntoPoint returns a point on the curve created from public keys in this way:
func (fc FactoryContext) HashPublicKeysIntoPoint(publicKeyPoints []Point, caseIdentifier []byte) Point {
	buff := append(PointsToBytes(publicKeyPoints), caseIdentifier...)
	x, y := fc.FindPointOnCurve(BuffToInt(fc.MakeDigest(buff)))
	return Point{x, y}
}

// FindPointOnCurve finds point x,y on the curve.
func (fc FactoryContext) FindPointOnCurve(value *big.Int) (*big.Int, *big.Int) {
	var x, y *big.Int
	var i int64
	var curve elliptic.Curve

	curveType, isTwistedBrainpool := BrainpoolParentCurves[fc.Curve.Params().Name]
	if isTwistedBrainpool {
		curve = curveType()
	} else {
		curve = fc.Curve
	}
	params := curve.Params()

	x = value.ModSqrt(value, params.P)

	for i = 0; i < 0x2a; i++ {
		if x != nil {
			y = CurvePolynomial(params, x)
			if y != nil {
				y = y.ModSqrt(y, params.P)
			}
			if y != nil {
				if curve.IsOnCurve(x, y) {
					if isTwistedBrainpool {
						x, y = fc.fromTwisted(x, y)
					}
					// log.Printf("Point for %#v found after %d steps.", fc.Curve.Params().Name, i)
					return x, y
				}
			}
		}
		x = value.ModSqrt(value.Add(value, big.NewInt(i)), params.P)
	}
	return nil, nil
}

// CurvePolynomial returns y calculaged from x.
// For curves is:  (x³ - 3x + B) % P or (x³ - 3x) % P
// For Secp256k1 is: (x³ + B) % P
func CurvePolynomial(params *elliptic.CurveParams, x *big.Int) *big.Int {
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x) // x³
	// Curve Secp256k1 does not have defined name.
	if params.Name != "" {
		// Curve is not Secp256k1.
		threeX := new(big.Int).Lsh(x, 1)
		threeX.Add(threeX, x)
		x3.Sub(x3, threeX)
	}
	if params.B != nil {
		x3.Add(x3, params.B)
	}
	x3.Mod(x3, params.P)
	return x3
}

// Brainpool type R must be untwisted.
func (fc FactoryContext) fromTwisted(tx, ty *big.Int) (*big.Int, *big.Int) {
	var x, y big.Int

	params := fc.Curve.Params()
	zinv2, zinv3 := GetZinv(params.Name)
	x.Mul(tx, zinv2)
	x.Mod(&x, params.P)
	y.Mul(ty, zinv3)
	y.Mod(&y, params.P)

	return &x, &y
}

// getRandomBytes returns bytes of random big integer.
func getRandomBytes(max *big.Int) []byte {
	value, err := rand.Int(rand.Reader, max)
	if err != nil {
		panic(err)
	}
	return value.Bytes()
}

// PointsToBytes converts Points to bytes.
func PointsToBytes(points []Point) []byte {
	var content []byte
	for _, point := range points {
		content = append(content, point.Bytes()...)
	}
	return content
}

// ConvertPublicKeysToPoints converts public keys into Points.
func ConvertPublicKeysToPoints(publicKeys []*ecdsa.PublicKey) []Point {
	points := make([]Point, len(publicKeys))
	for i, key := range publicKeys {
		points[i] = Point{key.X, key.Y}
	}
	return points
}

// BuffToInt creates big Int from buffer.
func BuffToInt(buff []byte) *big.Int {
	bn := new(big.Int)
	bn.SetBytes(buff)
	return bn
}

// CurveHashSupportedCombination returns true if the curve and hash combination are supported.
func CurveHashSupportedCombination(curve func() elliptic.Curve, hasher func() hash.Hash) bool {
	// ScalarBaseMult can't handle scalars > 256 bits
	// https://github.com/ethereum/go-ethereum/blob/v1.9.25/crypto/secp256k1/curve.go#L249
	if reflect.ValueOf(curve) == reflect.ValueOf(crypto.S256) {
		refHasher := reflect.ValueOf(hasher)
		if refHasher == reflect.ValueOf(sha3.New224) || refHasher == reflect.ValueOf(sha3.New256) {
			return true
		}
		return false
	}
	return true
}

// MakeSignature creates ring signature.
func MakeSignature(
	curve func() elliptic.Curve,
	hasher func() hash.Hash,
	privateKey *ecdsa.PrivateKey,
	publicKeys []*ecdsa.PublicKey,
	privateKeyPosition int,
	message []byte,
	caseIdentifier []byte,
) (int, *Signature) {

	if !CurveHashSupportedCombination(curve, hasher) {
		return UnsupportedCurveHashCombination, nil
	}

	n := len(publicKeys)
	if n < 2 { // less than two keys doesn't make sense
		return InsufficientNumberOfPublicKeys, nil
	}

	if privateKeyPosition >= n || privateKeyPosition < 0 {
		return PrivateKeyPositionOutOfRange, nil
	}

	// Check that key at position s is indeed the signer.
	if publicKeys[privateKeyPosition].X.Cmp(privateKey.X) != 0 || publicKeys[privateKeyPosition].Y.Cmp(privateKey.Y) != 0 {
		return PrivateKeyNotFitPublic, nil
	}

	curveOID, status1 := GetCurveOID(curve)
	if status1 != Success {
		return status1, nil
	}
	hasherOID, status2 := GetHasherOID(hasher)
	if status2 != Success {
		return status2, nil
	}

	fc := FactoryContext{Curve: curve(), Hasher: hasher}

	for _, pub := range publicKeys {
		if pub.Curve != fc.Curve {
			return UnexpectedCurveType, nil
		}
	}

	// # 4 A LSAG Signature Scheme
	//
	// Let *G* = ⧼g⧽ be a group of prime order *q* such that the underlying discrete
	// logarithm problem is intractable. Let *H<sub>1</sub>* : {0, 1}∗ → *Z<sub>q</sub>* and
	// *H<sub>2</sub>* : {0, 1}∗ → *G* be some statistically independent cryptographic hash functions.
	// For *i = 1, · · ·, n,* each user *i* has a distinct public key *y<sub>i</sub>*
	// and a private key *x<sub>i</sub>* such that *y<sub>i</sub> = g<sup>x<sub>i</sub></sup>*.
	// Let *L = {y<sub>1</sub>, · · ·, y<sub>n</sub>}* be the list of *n* public keys.

	H1 := fc.getSignatureDigest
	H2 := fc.HashPublicKeysIntoPoint

	params := fc.Curve.Params()
	q := params.N                    // curve order
	G := Point{params.Gx, params.Gy} // curve generator

	m := fc.MakeDigest(message)
	xπ := privateKey.D.Bytes() // secret multiplier
	π := privateKeyPosition
	L := ConvertPublicKeysToPoints(publicKeys)
	Lb := PointsToBytes(L)

	// ## 4.1 Signature Generation
	//
	// Given message *m* ∈ {0, 1}∗, list of public key *L = {y<sub>1</sub>, · · · , y<sub>n</sub>}*, private key
	// x<sub>π</sub> corresponding to *y<sub>π</sub> 1 ≤ π ≤ n*, the following algorithm generates a LSAG
	// signature.

	c := make([][]byte, n)
	s := make([][]byte, n)

	// ### Step 1
	// Compute *h = H<sub>2</sub>(L)* and *ỹ = h<sup>x<sub>π</sub></sup>*.

	h := H2(L, caseIdentifier)
	if h.x == nil {
		return PointWasNotFound, nil
	}
	y := fc.PointScalarMult(h, xπ)

	// ### Step 2
	// Pick *u ∈<sub>R</sub> Z<sub>q</sub>*, and compute
	//
	// *c<sub>π+1</sub> = H<sub>1</sub>(L, ỹ, m, g<sup>u</sup>, h<sup>u</sup>)*.

	u := getRandomBytes(q)
	c[(π+1)%n] = H1(Lb, y, m, fc.PointScalarMult(G, u), fc.PointScalarMult(h, u))

	// ### Step 3
	// For *i* = π+1, · · · , *n*, 1, · · · , π−1, pick *s<sub>i</sub> ∈<sub>R</sub> Z<sub>q</sub>* and compute
	//
	// *c<sub>i+1</sub> = H<sub>1</sub>(L, ỹ, m, g<sup>s<sub>i</sub></sup> y<sub>i</sub><sup>c<sub>i</sub></sup>,
	// h<sup>s<sub>i</sub></sup> ỹ<sup>c<sub>i</sub></sup>)*.
	var Gs, Lc, hs, yc Point

	for p := 1; p < n; p++ {
		i := (π + p) % n
		s[i] = getRandomBytes(q)
		Gs = fc.PointScalarMult(G, s[i])
		Lc = fc.PointScalarMult(L[i], c[i])
		hs = fc.PointScalarMult(h, s[i])
		yc = fc.PointScalarMult(y, c[i])
		c[(i+1)%n] = H1(Lb, y, m, fc.PointAdd(Gs, Lc), fc.PointAdd(hs, yc))
	}

	// ### Step 4
	// Compute *s<sub>π</sub>* = *u − x<sub>π</sub>c<sub>π</sub>* mod *q*.
	s[π] = new(big.Int).Mod(new(big.Int).Sub(BuffToInt(u), new(big.Int).Mul(BuffToInt(xπ), BuffToInt(c[π]))), q).Bytes()

	sign := Signature{
		Name:       Origin + " Signature",
		Version:    SignatureVersion,
		CurveOID:   curveOID,
		HasherOID:  hasherOID,
		KeyImage:   PointData{X: y.x.Bytes(), Y: y.y.Bytes()},
		Checksum:   c[0],
		Signatures: s,
	}

	return Success, &sign
}

// Create makes ring signature.
func Create(
	curve func() elliptic.Curve,
	hasher func() hash.Hash,
	privateKey *ecdsa.PrivateKey,
	publicKeys []*ecdsa.PublicKey,
	message []byte,
	caseIdentifier []byte,
) (int, *Signature) {

	var privateKeyPosition = -1

	for i, pub := range publicKeys {
		if pub.X.Cmp(privateKey.X) == 0 && pub.Y.Cmp(privateKey.Y) == 0 {
			privateKeyPosition = i
			break
		}
	}
	if privateKeyPosition == -1 {
		return PrivateKeyNotFoundAmongPublicKeys, nil
	}
	return MakeSignature(curve, hasher, privateKey, publicKeys, privateKeyPosition, message, caseIdentifier)
}

// Verify verifies signature.
func Verify(sign *Signature, publicKeys []*ecdsa.PublicKey, message []byte, caseIdentifier []byte) int {

	// # 4.2 Signature Verification
	// A public verifier checks a signature *σ<sub>L</sub>(m) = (c<sub>1</sub>, s<sub>1</sub>, · · ·, s<sub>n</sub>,
	// ỹ)* on a message *m*  and a list of public keys *L* as follows.

	var z1, z2 Point

	n := len(publicKeys)
	if len(sign.Signatures) != n {
		return IncorrectNumberOfSignatures
	}

	curve, success1 := GetCurve(sign.CurveOID)
	if !success1 {
		return OIDCurveNotFound
	}
	hasher, success2 := GetHasher(sign.HasherOID)
	if !success2 {
		return OIDHasherNotFound
	}
	if !CurveHashSupportedCombination(curve, hasher) {
		return UnsupportedCurveHashCombination
	}

	fc := FactoryContext{Curve: curve(), Hasher: hasher}

	for _, pub := range publicKeys {
		if pub.Curve != fc.Curve {
			return UnexpectedCurveType
		}
	}

	kx, ky := BuffToInt(sign.KeyImage.X), BuffToInt(sign.KeyImage.Y)
	if !fc.Curve.IsOnCurve(kx, ky) {
		return InvalidKeyImage
	}

	y := Point{kx, ky}

	H1 := fc.getSignatureDigest
	H2 := fc.HashPublicKeysIntoPoint

	params := fc.Curve.Params()
	G := Point{params.Gx, params.Gy}

	m := fc.MakeDigest(message)
	L := ConvertPublicKeysToPoints(publicKeys)
	Lb := PointsToBytes(L)

	c := make([][]byte, n)
	c[0] = sign.Checksum
	s := sign.Signatures

	// ### Step 1
	// Compute *h = H<sub>2</sub>(L)* and for *i = 1, · · · , n,* compute
	// z'<sub>i</sub> = g<sup>s<sub>i</sub></sup> y<sub>i</sub><sup>c<sub>i</sub></sup>,<br>
	// z<sub>i</sub>'' = h<sup>s<sub>i</sub></sup> ỹ<sup>c<sub>i</sub></sup>
	// and then *c<sub>i+1</sub> = H<sub>1</sub>(L, ỹ, m, z<sub>i</sub>', z<sub>i</sub>'')* if *i ≠ n*.

	h := H2(L, caseIdentifier)
	if h.x == nil {
		return PointWasNotFound
	}

	for i := 0; i < n; i++ {
		z1 = fc.PointAdd(fc.PointScalarMult(G, s[i]), fc.PointScalarMult(L[i], c[i]))
		z2 = fc.PointAdd(fc.PointScalarMult(h, s[i]), fc.PointScalarMult(y, c[i]))

		// ### Step 2.
		// Check whether *c<sub>1</sub> = H<sub>1</sub>(L, ỹ, m, z<sub>n</sub>', z<sub>n</sub>'')*.
		// If yes, accept. Otherwise, reject.
		if i < n-1 {
			c[i+1] = H1(Lb, y, m, z1, z2)
		} else {
			if bytes.Equal(sign.Checksum, H1(Lb, y, m, z1, z2)) {
				return Success
			}
		}
	}
	return IncorrectChecksum
}
