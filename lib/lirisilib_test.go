package main

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"testing"
	"unsafe"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/zbohm/lirisi/ring"
)

func readData(pointer unsafe.Pointer) []byte {
	size := *(*uint64)(pointer)
	if size > 0x300 {
		panic(size)
	}
	buffer := *(*[0x300]byte)(pointer)
	return buffer[8 : 8+size]
}

func TestBytesToPointer(t *testing.T) {
	pointer := bytesToPointer([]byte("SUCCESS"))
	data := readData(pointer)
	if string(data) != "SUCCESS" {
		t.Error("Data does not match.")
	}
}

func TestCreatePrivateKey(t *testing.T) {
	pointer := CreatePrivateKey()
	bytes := readData(pointer)
	privKey, err := crypto.ToECDSA(bytes)
	if err != nil {
		t.Error(err)
	}
	dataType := fmt.Sprintf("%T", privKey)
	if dataType != "*ecdsa.PrivateKey" {
		t.Errorf("Unexpected data type: '%s'", dataType)
	}
}

func TestExtractPublicKey(t *testing.T) {
	privKey, err := crypto.GenerateKey()
	if err != nil {
		t.Error(err)
	}
	bytes := crypto.FromECDSA(privKey)
	pointer := ExtractPublicKey(bytes)
	bPub := readData(pointer)
	pubKey, err := crypto.UnmarshalPubkey(bPub)
	if err != nil {
		t.Error(err)
	}
	dataType := fmt.Sprintf("%T", pubKey)
	if dataType != "*ecdsa.PublicKey" {
		t.Errorf("Unexpected data type: '%s'", dataType)
	}
}

func TestCreateRingOfPublicKeys(t *testing.T) {
	size := 3
	pointer := CreateRingOfPublicKeys(size)
	ring := readData(pointer)
	if len(ring) != pubKeyBytesSize*size {
		t.Errorf("Unexpected data size: %d (instead %d)", len(ring), pubKeyBytesSize*size)
	}
	for i := 0; i < size; i++ {
		pos := i * pubKeyBytesSize
		pubKey, err := crypto.UnmarshalPubkey(ring[pos : pos+pubKeyBytesSize])
		if err != nil {
			t.Error(err)
		}
		dataType := fmt.Sprintf("%T", pubKey)
		if dataType != "*ecdsa.PublicKey" {
			t.Errorf("Unexpected data type[%d]: '%s'", i, dataType)
		}
	}
}

func createPublicKeyList(size int) ring.PublicKeysList {
	ring := make(ring.PublicKeysList, size)
	for i := 0; i < size; i++ {
		privkey, err := crypto.GenerateKey()
		if err != nil {
			panic(err)
		}
		ring[i] = privkey.Public().(*ecdsa.PublicKey)
	}
	return ring
}

func TestCreateSignature(t *testing.T) {
	privKey, err := crypto.GenerateKey()
	if err != nil {
		t.Error(err)
	}
	ringPubs := createPublicKeyList(3)
	pubKey := privKey.Public().(*ecdsa.PublicKey)
	ringPubs = append(ringPubs, pubKey)
	var buffRing bytes.Buffer
	for _, pubKey := range ringPubs {
		if _, err := buffRing.Write(crypto.FromECDSAPub(pubKey)); err != nil {
			t.Error(err)
		}
	}
	bytesPriv := crypto.FromECDSA(privKey)

	message := []byte("Hello world!")
	pointer := CreateSignature(message, buffRing.Bytes(), bytesPriv)
	signBytes := readData(pointer)
	sign, err := ring.FromBytes(signBytes)
	if err != nil {
		t.Error(err)
	}
	dataType := fmt.Sprintf("%T", sign)
	if dataType != "*ring.Signature" {
		t.Errorf("Unexpected data type: '%s'", dataType)
	}
}

func createSignature(t *testing.T, message []byte) (*ring.Signature, ring.PublicKeysList) {
	privKey, err := crypto.GenerateKey()
	if err != nil {
		t.Error(err)
	}
	pubsRing := createPublicKeyList(3)
	pubKey := privKey.Public().(*ecdsa.PublicKey)
	pubsRing = append(pubsRing, pubKey)
	sign, err := ring.CreateSign(message, pubsRing, privKey)
	if err != nil {
		t.Error(err)
	}
	return sign, pubsRing
}

func TestVerifySignature(t *testing.T) {
	message := []byte("Hello world!")
	sign, pubsRing := createSignature(t, message)
	var buffRing bytes.Buffer
	for _, pubKey := range pubsRing {
		if _, err := buffRing.Write(crypto.FromECDSAPub(pubKey)); err != nil {
			t.Error(err)
		}
	}
	result := VerifySignature(message, buffRing.Bytes(), sign.ToBytes())
	if !result {
		t.Error("Verify sign failed.")
	}
}

func TestSignToPEM(t *testing.T) {
	message := []byte("Hello world!")
	sign, _ := createSignature(t, message)
	pointer := SignToPEM(sign.ToBytes())
	pem := readData(pointer)
	sign, err := ring.FromPEM(pem)
	if err != nil {
		t.Error(err)
	}
	dataType := fmt.Sprintf("%T", sign)
	if dataType != "*ring.Signature" {
		t.Errorf("Unexpected data type: '%s'", dataType)
	}
}

func TestPEMtoSign(t *testing.T) {
	message := []byte("Hello world!")
	sign, _ := createSignature(t, message)
	bytes, err := sign.ToPEM()
	if err != nil {
		t.Error(err)
	}
	pointer := PEMtoSign(bytes)
	signBytes := readData(pointer)
	sign2, err := ring.FromBytes(signBytes)
	if err != nil {
		t.Error(err)
	}
	dataType := fmt.Sprintf("%T", sign2)
	if dataType != "*ring.Signature" {
		t.Errorf("Unexpected data type: '%s'", dataType)
	}
}

func TestGetKeyImage(t *testing.T) {
	message := []byte("Hello world!")
	sign, _ := createSignature(t, message)
	pointer := GetKeyImage(sign.ToBytes())
	imageBytes := readData(pointer)
	if len(imageBytes) != 64 {
		t.Errorf("Unexpected imageBytes size: %d", len(imageBytes))
	}
	x := new(big.Int).SetBytes(imageBytes[:32])
	y := new(big.Int).SetBytes(imageBytes[32:])
	if sign.I.X.Cmp(x) != 0 {
		t.Error("Image.X does not match.")
	}
	if sign.I.Y.Cmp(y) != 0 {
		t.Error("Image.Y does not match.")
	}
}
