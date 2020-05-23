package ring

import (
	"crypto/ecdsa"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func compareSignatures(t *testing.T, sig1, sig2 *Signature) {
	if sig1.I.X.Cmp(sig2.I.X) != 0 {
		t.Error("Key Image.X does not match.")
	}
	if sig1.I.Y.Cmp(sig2.I.Y) != 0 {
		t.Error("Key Image.Y does not match.")
	}
	if sig1.C.Cmp(sig2.C) != 0 {
		t.Error("Key C does not match.")
	}
	if len(sig1.S) != len(sig2.S) {
		t.Error("Size of S does not match.")
	}
	for i := range sig1.S {
		if sig1.S[i].Cmp(sig2.S[i]) != 0 {
			t.Errorf("S[%d] does not match.", i)
		}
	}
}

func createSignature(t *testing.T) *Signature {
	privkey, err := crypto.GenerateKey()
	if err != nil {
		t.Error(err)
	}
	pubKeys := createPublicKeyList(2)
	pubKeys = append(pubKeys, privkey.Public().(*ecdsa.PublicKey))
	sig, err := Sign(message, pubKeys, privkey, 2)
	if err != nil {
		t.Error(err)
	}
	return sig
}

func TestToBytesFromBytes(t *testing.T) {
	sig1 := createSignature(t)
	bytes := sig1.ToBytes()
	sig2, err := FromBytes(bytes)
	if err != nil {
		t.Error(err)
	}
	compareSignatures(t, sig1, sig2)
}

func TestMarshalUnmarshal(t *testing.T) {
	sig1 := createSignature(t)
	bytes, err := sig1.Marshal()
	if err != nil {
		t.Error(err)
	}
	sig2, err := Unmarshal(bytes)
	if err != nil {
		t.Error(err)
	}
	compareSignatures(t, sig1, sig2)
}

func TestArmorDearmor(t *testing.T) {
	sig1 := createSignature(t)
	bytes, err := sig1.Armor()
	if err != nil {
		t.Error(err)
	}
	sig2, err := Dearmor(bytes)
	if err != nil {
		t.Error(err)
	}
	compareSignatures(t, sig1, sig2)
}

func TestPEM(t *testing.T) {
	sig1 := createSignature(t)
	bytes, err := sig1.ToPEM()
	if err != nil {
		t.Error(err)
	}
	sig2, err := FromPEM(bytes)
	if err != nil {
		t.Error(err)
	}
	compareSignatures(t, sig1, sig2)
}

func TestPEMUnknownType(t *testing.T) {
	var bytes = []byte(`
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlRuRnThUjU8/prwYxbty
WPT9pURI3lbsKMiB6Fn/VHOKE13p4D8xgOCADpdRagdT6n4etr9atzDKUSvpMtR3
-----END PUBLIC KEY-----`)
	sig, err := FromPEM(bytes)
	if fmt.Sprintf("%s", err) != "unknown PEM type" {
		t.Errorf("unexpected error message: '%s'", err)
	}
	if sig != nil {
		t.Error("signature is not nil")
	}
}
