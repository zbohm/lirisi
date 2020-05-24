package main

import (
	"encoding/binary"
	"unsafe"

	"github.com/ethereum/go-ethereum/crypto"
)

import "C"

// Compile this library:
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
func ExtractPublicKey(privKey []byte) unsafe.Pointer {
	data := privKey[:] // TODO:...
	return bytesToPointer(data)
}

func main() {}
