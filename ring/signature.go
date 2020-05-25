package ring

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"
)

// PrivKeyImage is unique private key identifier.
type PrivKeyImage struct {
	X *big.Int
	Y *big.Int
}

// Signature is struct with signature data.
type Signature struct {
	I *PrivKeyImage // private key image
	C *big.Int      // ring signature value
	S []*big.Int    // ring signature list of faked secret keys
}

// PublicKeysList is the list of public keys.
type PublicKeysList []*ecdsa.PublicKey

var curve elliptic.Curve

// GetPosition returns the position of given public key in the list of public keys.
func GetPosition(ring PublicKeysList, pubkey *ecdsa.PublicKey) (int, bool) {
	for i, pub := range ring {
		if pub.X.Cmp(pubkey.X) == 0 && pub.Y.Cmp(pubkey.Y) == 0 {
			return i, true
		}
	}
	return -1, false
}

// GenKeyImage calculates key image I = x * H_p(P) where H_p is a hash function that returns a point
// H_p(P) = sha3(P) * G
func GenKeyImage(privkey *ecdsa.PrivateKey) *PrivKeyImage {
	pubkey := privkey.Public().(*ecdsa.PublicKey)
	image := new(PrivKeyImage)

	// calculate sha3(P)
	hX, hY := hashPoint(pubkey)

	// calculate H_p(P) = x * sha3(P) * G
	image.X, image.Y = privkey.Curve.ScalarMult(hX, hY, privkey.D.Bytes())
	return image
}

// hashPoint creates hash of elliptic Point.
func hashPoint(p *ecdsa.PublicKey) (*big.Int, *big.Int) {
	hash := sha3.Sum256(append(p.X.Bytes(), p.Y.Bytes()...))
	return p.Curve.ScalarBaseMult(hash[:])
}

// Sign creates ring signature from list of public keys given inputs:
// message: a byte array message to be signed
// ring: array of *ecdsa.PublicKeys
// privkey: *ecdsa.PrivateKey of signer
// s: secret index of signer in ring
func Sign(message []byte, ring PublicKeysList, privkey *ecdsa.PrivateKey, s int) (*Signature, error) {
	// check ringsize > 1
	msgHash := sha3.Sum256(message)
	ringsize := len(ring)
	if ringsize < 2 {
		return nil, errors.New("size of ring less than two")
	} else if s >= ringsize || s < 0 {
		return nil, errors.New("secret index out of range of ring size")
	}

	// setup
	pubkey := &privkey.PublicKey
	curve := pubkey.Curve
	sig := new(Signature)

	// check that curve of public key exists
	if curve == nil {
		return nil, errors.New("no curve in public key")
	}

	// check that key at index s is indeed the signer
	if ring[s].X.Cmp(pubkey.X) != 0 || ring[s].Y.Cmp(pubkey.Y) != 0 {
		return nil, errors.New("secret index in ring is not signer")
	}

	// generate private key image
	image := GenKeyImage(privkey)
	sig.I = image

	// start at c[1]
	// pick random scalar u (glue value), calculate c[1] = H(m, u*G) where H is a hash function and G is the base point of the curve
	C := make([]*big.Int, ringsize)
	S := make([]*big.Int, ringsize)

	// pick random scalar u
	u, err := rand.Int(rand.Reader, curve.Params().P)
	if err != nil {
		return nil, err
	}

	// start at secret index s
	// compute L_s = u*G
	lX, lY := curve.ScalarBaseMult(u.Bytes())
	// compute R_s = u*H_p(P[s])
	hX, hY := hashPoint(pubkey)
	rX, rY := curve.ScalarMult(hX, hY, u.Bytes())

	l := append(lX.Bytes(), lY.Bytes()...)
	r := append(rX.Bytes(), rY.Bytes()...)

	// concatenate m and u*G and calculate c[s+1] = H(m, L_s, R_s)
	CI := sha3.Sum256(append(msgHash[:], append(l, r...)...))
	idx := (s + 1) % ringsize
	C[idx] = new(big.Int).SetBytes(CI[:])
	curveParams := curve.Params().P

	// start loop at s+1
	for i := 1; i < ringsize; i++ {
		idx := (s + i) % ringsize

		// pick random scalar sI
		sI, err := rand.Int(rand.Reader, curveParams)
		S[idx] = sI
		if err != nil {
			return nil, err
		}

		if ring[idx] == nil {
			return nil, fmt.Errorf("No public key at index %d", idx)
		}
		if ring[idx].Curve == nil {
			return nil, fmt.Errorf("No curve at index %d", idx)
		}

		// calculate L_i = s_i*G + c_i*P_i
		px, py := curve.ScalarMult(ring[idx].X, ring[idx].Y, C[idx].Bytes()) // px, py = c_i*P_i
		sx, sy := curve.ScalarBaseMult(sI.Bytes())                           // sx, sy = s[n-1]*G
		lX, lY := curve.Add(sx, sy, px, py)

		// calculate R_i = sI*H_p(P_i) + c_i*I
		px, py = curve.ScalarMult(image.X, image.Y, C[idx].Bytes()) // px, py = c_i*I
		hx, hy := hashPoint(ring[idx])
		sx, sy = curve.ScalarMult(hx, hy, sI.Bytes()) // sx, sy = s[n-1]*H_p(P_i)
		rX, rY := curve.Add(sx, sy, px, py)

		// calculate c[i+1] = H(m, L_i, R_i)
		l := append(lX.Bytes(), lY.Bytes()...)
		r := append(rX.Bytes(), rY.Bytes()...)
		CI = sha3.Sum256(append(msgHash[:], append(l, r...)...))

		if i == ringsize-1 {
			C[s] = new(big.Int).SetBytes(CI[:])
		} else {
			C[(idx+1)%ringsize] = new(big.Int).SetBytes(CI[:])
		}
	}

	// close ring by finding S[s] = ( u - c[s]*k[s] ) mod P where k[s] is the private key and P is the order of the curve
	S[s] = new(big.Int).Mod(new(big.Int).Sub(u, new(big.Int).Mul(C[s], privkey.D)), curve.Params().N)

	// check that u*G = S[s]*G + c[s]*P[s]
	ux, uy := curve.ScalarBaseMult(u.Bytes()) // u*G
	px, py := curve.ScalarMult(ring[s].X, ring[s].Y, C[s].Bytes())
	sx, sy := curve.ScalarBaseMult(S[s].Bytes())
	lX, lY = curve.Add(sx, sy, px, py)

	// check that u*H_p(P[s]) = S[s]*H_p(P[s]) + C[s]*I
	px, py = curve.ScalarMult(image.X, image.Y, C[s].Bytes()) // px, py = C[s]*I
	hx, hy := hashPoint(ring[s])
	tx, ty := curve.ScalarMult(hx, hy, u.Bytes())
	sx, sy = curve.ScalarMult(hx, hy, S[s].Bytes()) // sx, sy = S[s]*H_p(P[s])
	rX, rY = curve.Add(sx, sy, px, py)

	l = append(lX.Bytes(), lY.Bytes()...)
	r = append(rX.Bytes(), rY.Bytes()...)

	// check that H(m, L[s], R[s]) == C[s+1]
	CI = sha3.Sum256(append(msgHash[:], append(l, r...)...))

	if !bytes.Equal(ux.Bytes(), lX.Bytes()) || !bytes.Equal(uy.Bytes(), lY.Bytes()) || !bytes.Equal(tx.Bytes(), rX.Bytes()) || !bytes.Equal(ty.Bytes(), rY.Bytes()) {
		return nil, errors.New("error closing ring")
	}

	// everything ok, add values to signature
	sig.S = S
	sig.C = C[0]

	return sig, nil
}

// CreateSign creates ring signature from list of public keys given inputs:
// message: a byte array message to be signed
// ring: array of *ecdsa.PublicKeys
// privkey: *ecdsa.PrivateKey of signer
func CreateSign(message []byte, ring PublicKeysList, privkey *ecdsa.PrivateKey) (*Signature, error) {
	pubkey := privkey.Public().(*ecdsa.PublicKey)
	keyPos, found := GetPosition(ring, pubkey)
	if !found {
		return nil, errors.New("position of public key was not found")
	}
	return Sign(message, ring, privkey, keyPos)
}

// VerifySign verifies ring signature contained in Signature struct
// message: message to be signed
// ring: array of *ecdsa.PublicKeys
// returns true if a valid signature, false otherwise
func VerifySign(sig *Signature, message []byte, ring PublicKeysList) bool {
	ringsize := len(sig.S) // sig.Size
	if ringsize != len(ring) {
		return false
	}
	msgHash := sha3.Sum256(message)

	if curve == nil {
		curve = crypto.S256()
	}

	S := sig.S
	C := make([]*big.Int, ringsize)
	C[0] = sig.C
	image := sig.I

	// calculate c[i+1] = H(m, s[i]*G + c[i]*P[i])
	// and c[0] = H)(m, s[n-1]*G + c[n-1]*P[n-1]) where n is the ring size
	for i := 0; i < ringsize; i++ {
		// calculate L_i = s_i*G + c_i*P_i
		px, py := curve.ScalarMult(ring[i].X, ring[i].Y, C[i].Bytes()) // px, py = c_i*P_i
		sx, sy := curve.ScalarBaseMult(S[i].Bytes())                   // sx, sy = s[i]*G
		lX, lY := curve.Add(sx, sy, px, py)

		// calculate R_i = s_i*H_p(P_i) + c_i*I
		px, py = curve.ScalarMult(image.X, image.Y, C[i].Bytes()) // px, py = c[i]*I
		hx, hy := hashPoint(ring[i])
		sx, sy = curve.ScalarMult(hx, hy, S[i].Bytes()) // sx, sy = s[i]*H_p(P[i])
		rX, rY := curve.Add(sx, sy, px, py)

		// calculate c[i+1] = H(m, L_i, R_i)
		l := append(lX.Bytes(), lY.Bytes()...)
		r := append(rX.Bytes(), rY.Bytes()...)
		CI := sha3.Sum256(append(msgHash[:], append(l, r...)...))

		if i == ringsize-1 {
			C[0] = new(big.Int).SetBytes(CI[:])
		} else {
			C[i+1] = new(big.Int).SetBytes(CI[:])
		}
	}

	return bytes.Equal(sig.C.Bytes(), C[0].Bytes())
}
