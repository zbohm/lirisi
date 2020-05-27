package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"log"
	"unsafe"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/zbohm/lirisi/ring"
)

import "C"

// Compile this library for calling functions from other languages:
// go build -o wrappers/lirisilib.so -buildmode=c-shared lib/lirisilib.go

// bytesToPointer encode bytes into unsafe pointer
func bytesToPointer(content []byte) unsafe.Pointer {
	buff := make([]byte, 8)
	binary.LittleEndian.PutUint64(buff, uint64(len(content)))
	return C.CBytes(append(buff, content...))
}

// CreatePrivateKey create private key and returns bytes.
//export CreatePrivateKey
func CreatePrivateKey() unsafe.Pointer {
	privKey, err := crypto.GenerateKey()
	if err != nil {
		panic(err)
	}
	return bytesToPointer(crypto.FromECDSA(privKey))
}

// ExtractPublicKey extract public key from private key.
//export ExtractPublicKey
func ExtractPublicKey(privKeyBytes []byte) unsafe.Pointer {
	privKey, err := crypto.ToECDSA(privKeyBytes)
	if err != nil {
		panic(err)
	}
	pubKey := privKey.Public().(*ecdsa.PublicKey)
	data := crypto.FromECDSAPub(pubKey)
	return bytesToPointer(data)
}

// Lenth of bytes serialized public key.
const pubKeyBytesSize = 65

// GetPubKeyBytesSize returns the lenth of bytes serialized public key.
//export GetPubKeyBytesSize
func GetPubKeyBytesSize() int {
	return pubKeyBytesSize
}

// CreateRingOfPublicKeys creates the list of public keys for testing purposes.
//export CreateRingOfPublicKeys
func CreateRingOfPublicKeys(size int) unsafe.Pointer {
	var buffer bytes.Buffer
	for i := 0; i < size; i++ {
		privkey, err := crypto.GenerateKey()
		if err != nil {
			log.Fatal(err)
		}
		pubKey := privkey.Public().(*ecdsa.PublicKey)
		if nBytes, err := buffer.Write(crypto.FromECDSAPub(pubKey)); err != nil {
			log.Fatal(err)
		} else if nBytes != pubKeyBytesSize {
			log.Fatal("unexpected public key length")
		}
	}
	return bytesToPointer(buffer.Bytes())
}

// Recover ring of public keys.
func recoverRing(pubKeysRing []byte) ring.PublicKeysList {
	size := len(pubKeysRing) / pubKeyBytesSize
	pubsRing := make(ring.PublicKeysList, size)
	for i := 0; i < size; i++ {
		n := i * pubKeyBytesSize
		pubBytes := pubKeysRing[n : n+pubKeyBytesSize]
		pub, err := crypto.UnmarshalPubkey(pubBytes)
		if err != nil {
			log.Fatal(err)
		}
		pubsRing[i] = pub
	}
	return pubsRing
}

// CreateSignature creates the signature and save it to PEM.
//export CreateSignature
func CreateSignature(message, pubKeysRing, privKeyBytes []byte) unsafe.Pointer {
	// Recover ring of public keys.
	pubsRing := recoverRing(pubKeysRing)
	// Reconstruct private key.
	privKey, err := crypto.ToECDSA(privKeyBytes)
	if err != nil {
		log.Fatal(err)
	}
	sign, err := ring.CreateSign(message, pubsRing, privKey)
	if err != nil {
		log.Fatal(err)
	}
	return bytesToPointer(sign.ToBytes())
}

// VerifySignature verify signature.
//export VerifySignature
func VerifySignature(message, pubKeysRing, signBytes []byte) bool {
	// Recover ring of public keys.
	pubsRing := recoverRing(pubKeysRing)
	sign, err := ring.FromBytes(signBytes)
	if err != nil {
		log.Fatal(err)
	}
	return ring.VerifySign(sign, message, pubsRing)
}

// SignToPEM converts signature to PEM.
//export SignToPEM
func SignToPEM(data []byte) unsafe.Pointer {
	sign, err := ring.FromBytes(data)
	if err != nil {
		log.Fatal(err)
	}
	pem, err := sign.ToPEM()
	if err != nil {
		log.Fatal(err)
	}
	return bytesToPointer(pem)
}

// PEMtoSign converts PEM bytes to bytes for signature.
//export PEMtoSign
func PEMtoSign(data []byte) unsafe.Pointer {
	sign, err := ring.FromPEM(data)
	if err != nil {
		log.Fatal(err)
	}
	return bytesToPointer(sign.ToBytes())
}

// GetKeyImage extract KeyImage from signature bytes.
//export GetKeyImage
func GetKeyImage(data []byte) unsafe.Pointer {
	sign, err := ring.FromBytes(data)
	if err != nil {
		log.Fatal(err)
	}
	return bytesToPointer(sign.ImageToBytes())
}

func main() {}
