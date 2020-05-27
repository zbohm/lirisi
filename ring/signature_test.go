package ring

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"
)

var message = []byte(`
	One Ring allow voting them all,
	One Ring to collect them,
	One Ring to hide them all, and in the privacy bind them.
`)

func bigInt(text string) *big.Int {
	bytes, err := hex.DecodeString(text)
	if err != nil {
		panic(err)
	}
	return new(big.Int).SetBytes(bytes)
}

func createPublicKeyList(size int) PublicKeysList {
	ring := make(PublicKeysList, size)
	for i := 0; i < size; i++ {
		privkey, err := crypto.GenerateKey()
		if err != nil {
			panic(err)
		}
		ring[i] = privkey.Public().(*ecdsa.PublicKey)
	}
	return ring
}

func TestHashPoint(t *testing.T) {
	privkey, err := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")
	if err != nil {
		t.Error(err)
	}
	hX, hY := hashPoint(privkey.Public().(*ecdsa.PublicKey))

	rX := bigInt("edc319b81ddeee95a502d2ab438a3df9d4cac548b3e512a278b142fa27511756")
	rY := bigInt("9d18db2d7fade666eafc6fe09d8440e03fe84b7604aa935dd5facb2b4baa05c3")
	if hX.Cmp(rX) != 0 {
		t.Error("X is not equal")
	}
	if hY.Cmp(rY) != 0 {
		t.Error("Y is not equal")
	}
}

func testImage(t *testing.T, image *PrivKeyImage) {
	rX := bigInt("187be7294d837e3557a5d6827d87a33dc609a339e82be398d2fdd894e7a3e854")
	rY := bigInt("99ee5daf57acce886b9e254c27d46bddc7ede6c443d5f6f56a3ba715b758b6ac")
	if image.X.Cmp(rX) != 0 {
		t.Error("image.X is not equal")
	}
	if image.Y.Cmp(rY) != 0 {
		t.Error("image.Y is not equal")
	}
}

func TestGenKeyImage(t *testing.T) {
	privkey, _ := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")
	image := GenKeyImage(privkey)
	testImage(t, image)
}

func TestGetPosition(t *testing.T) {
	privkey, err := crypto.GenerateKey()
	if err != nil {
		t.Error(err)
	}
	pubkey := privkey.Public().(*ecdsa.PublicKey)
	pubKeys := createPublicKeyList(3)
	pubKeys = append(pubKeys, pubkey)
	if pos, found := GetPosition(pubKeys, pubkey); found {
		if pos != 3 {
			t.Errorf("Unexpected position %d of the public key.", pos)
		}
	} else {
		t.Error("Position was not found.")
	}
	privkey2, err := crypto.GenerateKey()
	if err != nil {
		t.Error(err)
	}
	pubkey2 := privkey2.Public().(*ecdsa.PublicKey)
	if pos, found := GetPosition(pubKeys, pubkey2); found {
		t.Errorf("Position was found at %d even the key is not present.", pos)
	} else {
		if pos != -1 {
			t.Error("Unexpected position value.")
		}
	}
}

func TestSign(t *testing.T) {
	privkey, err := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")
	if err != nil {
		t.Error(err)
	}
	pubKeys := createPublicKeyList(3)
	pubKeys = append(pubKeys, privkey.Public().(*ecdsa.PublicKey))
	sig, err := Sign(message, pubKeys, privkey, 3)
	if err != nil {
		t.Error(err)
	}
	testImage(t, sig.I)
	if len(sig.S) != 4 {
		t.Error("unexpected size of sign.S")
	}
}

func TestCreateSign(t *testing.T) {
	privkey, err := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")
	if err != nil {
		t.Error(err)
	}
	pubKeys := createPublicKeyList(2)
	pubKeys = append(pubKeys, privkey.Public().(*ecdsa.PublicKey))
	pubKeys = append(pubKeys, createPublicKeyList(2)...)
	sig, err := CreateSign(message, pubKeys, privkey)
	if err != nil {
		t.Error(err)
	}
	testImage(t, sig.I)
	if len(sig.S) != 5 {
		t.Error("unexpected size of sign.S")
	}
	ver := VerifySign(sig, message, pubKeys)
	if !ver {
		t.Error("Verify sign failed")
	}
}

func TestCreateSignPositionNotFound(t *testing.T) {
	privkey, err := crypto.GenerateKey()
	if err != nil {
		t.Error(err)
	}
	pubKeys := createPublicKeyList(2)
	sig, err := CreateSign(message, pubKeys, privkey)
	if fmt.Sprintf("%s", err) != "position of public key was not found" {
		t.Errorf("unexpected error message: '%s'", err)
	}
	if sig != nil {
		t.Error("signature is not nil")
	}
}

func TestSignInsufficientRignSize(t *testing.T) {
	privkey, err := crypto.GenerateKey()
	if err != nil {
		t.Error(err)
	}
	pubKeys := make(PublicKeysList, 1)
	pubKeys[0] = privkey.Public().(*ecdsa.PublicKey)
	sig, err := Sign(message, pubKeys, privkey, 0)
	if fmt.Sprintf("%s", err) != "size of ring less than two" {
		t.Errorf("unexpected error message: '%s'", err)
	}
	if sig != nil {
		t.Error("signature is not nil")
	}
}

func TestSignPrivateOutOfRange(t *testing.T) {
	privkey, err := crypto.GenerateKey()
	if err != nil {
		t.Error(err)
	}
	pubKeys := createPublicKeyList(3)
	pubKeys = append(pubKeys, privkey.Public().(*ecdsa.PublicKey))
	sig, err := Sign(message, pubKeys, privkey, 42)
	if fmt.Sprintf("%s", err) != "secret index out of range of ring size" {
		t.Errorf("unexpected error message: '%s'", err)
	}
	if sig != nil {
		t.Error("signature is not nil")
	}
}

func TestSignPrivateLessZero(t *testing.T) {
	privkey, err := crypto.GenerateKey()
	if err != nil {
		t.Error(err)
	}
	pubKeys := createPublicKeyList(1)
	pubKeys = append(pubKeys, privkey.Public().(*ecdsa.PublicKey))
	sig, err := Sign(message, pubKeys, privkey, -1)
	if fmt.Sprintf("%s", err) != "secret index out of range of ring size" {
		t.Errorf("unexpected error message: '%s'", err)
	}
	if sig != nil {
		t.Error("signature is not nil")
	}
}

func TestSignPrivateNotMatchPublic(t *testing.T) {
	privkey, err := crypto.GenerateKey()
	if err != nil {
		t.Error(err)
	}
	pubKeys := createPublicKeyList(1)
	pubKeys = append(pubKeys, privkey.Public().(*ecdsa.PublicKey))
	sig, err := Sign(message, pubKeys, privkey, 0)
	if fmt.Sprintf("%s", err) != "secret index in ring is not signer" {
		t.Errorf("unexpected error message: '%s'", err)
	}
	if sig != nil {
		t.Error("signature is not nil")
	}
}

func TestVerifySign(t *testing.T) {
	privkey, err := crypto.GenerateKey()
	if err != nil {
		t.Error(err)
	}
	pubKeys := createPublicKeyList(3)
	pubKeys = append(pubKeys, privkey.Public().(*ecdsa.PublicKey))
	sig, err := Sign(message, pubKeys, privkey, 3)
	if err != nil {
		t.Error(err)
	}
	ver := VerifySign(sig, message, pubKeys)
	if !ver {
		t.Error("Verify sign failed")
	}
}

func TestVerifySignDifferentPublicKeysListOrder(t *testing.T) {
	privkey, err := crypto.GenerateKey()
	if err != nil {
		t.Error(err)
	}
	pubKeys := createPublicKeyList(3)
	pubKeys = append(pubKeys, privkey.Public().(*ecdsa.PublicKey))
	sig, err := Sign(message, pubKeys, privkey, 3)
	if err != nil {
		t.Error(err)
	}
	pubKeys[1], pubKeys[2] = pubKeys[2], pubKeys[1]
	ver := VerifySign(sig, message, pubKeys)
	if ver {
		t.Error("unexpected Verify sign success")
	}
}

func TestVerifySignDifferentMessage(t *testing.T) {
	privkey, err := crypto.GenerateKey()
	if err != nil {
		t.Error(err)
	}
	pubKeys := createPublicKeyList(3)
	pubKeys = append(pubKeys, privkey.Public().(*ecdsa.PublicKey))
	sig, err := Sign(message, pubKeys, privkey, 3)
	if err != nil {
		t.Error(err)
	}
	ver := VerifySign(sig, []byte("Thanks for all the fish!"), pubKeys)
	if ver {
		t.Error("unexpected Verify sign success")
	}
}

func TestVerifySignMissingPublicKey(t *testing.T) {
	privkey, err := crypto.GenerateKey()
	if err != nil {
		t.Error(err)
	}
	pubKeys := createPublicKeyList(3)
	pubKeys = append(pubKeys, privkey.Public().(*ecdsa.PublicKey))
	sig, err := Sign(message, pubKeys, privkey, 3)
	if err != nil {
		t.Error(err)
	}
	pubKeys = pubKeys[:len(pubKeys)-1]
	ver := VerifySign(sig, message, pubKeys)
	if ver {
		t.Error("unexpected Verify sign success")
	}
}

// https://kewde.github.io/urs Unique Ring Signatures (URS) - broken cryptography
func TestFindPubKey(t *testing.T) {
	privkey, err := crypto.GenerateKey()
	if err != nil {
		t.Error(err)
	}
	pubKey := privkey.Public().(*ecdsa.PublicKey)
	pubKeys := createPublicKeyList(3)
	pubKeys = append(pubKeys, pubKey)
	sig, err := Sign(message, pubKeys, privkey, 3)
	if err != nil {
		t.Error(err)
	}
	ver := VerifySign(sig, message, pubKeys)
	if !ver {
		t.Error("Verify sign failed")
	}
	curve := pubKey.Curve
	msgHash := sha3.Sum256(message)
	for j := 0; j < len(pubKeys); j++ {
		rx, ry := curve.ScalarMult(pubKeys[j].X, pubKeys[j].Y, msgHash[:])
		if sig.I.X.Cmp(rx) == 0 && sig.I.Y.Cmp(ry) == 0 {
			t.Errorf("Exploit! Found signing key: %d\nX: %x\nY: %x\n", j, rx, ry)
		}
	}
}
