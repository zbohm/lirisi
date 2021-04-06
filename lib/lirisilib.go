package main

import (
	"C"
	"encoding/binary"
	"unsafe"

	"github.com/zbohm/lirisi/client"
)

// Compile this library for calling functions from other languages:
// go build -o wrappers/lirisilib.so -buildmode=c-shared lib/lirisilib.go

// bytesToPointer encode bytes into unsafe pointer
func bytesToPointer(status int, content []byte) unsafe.Pointer {
	buff := make([]byte, 16)
	binary.LittleEndian.PutUint64(buff, uint64(status))
	binary.LittleEndian.PutUint64(buff[8:], uint64(len(content)))
	buff = append(buff, content...)
	return C.CBytes(buff)
}

// arrayOfByteArraysToPointer encode array of byte arrays into unsafe pointer
func arrayOfByteArraysToPointer(status int, contents [][]byte) unsafe.Pointer {
	buff := make([]byte, 16)
	binary.LittleEndian.PutUint64(buff, uint64(status))
	binary.LittleEndian.PutUint64(buff[8:], uint64(len(contents)))
	for _, item := range contents {
		size := make([]byte, 8)
		binary.LittleEndian.PutUint64(size, uint64(len(item)))
		buff = append(buff, size...)
		buff = append(buff, item...)
	}
	return C.CBytes(buff)
}

// SignatureKeyImage outputs signature key image.
//export SignatureKeyImage
func SignatureKeyImage(content []byte, separator bool) unsafe.Pointer {
	return bytesToPointer(client.SignatureKeyImage(content, separator))
}

// FoldPublicKeys folds public keys into one content.
//export FoldPublicKeys
func FoldPublicKeys(pubKeysContent [][]byte, hashName, outFormat, order string) unsafe.Pointer {
	return bytesToPointer(client.FoldPublicKeys(pubKeysContent, hashName, outFormat, order))
}

// CreateSignature creates signature.
//export CreateSignature
func CreateSignature(foldedPublicKeys, privateKeyContent, message, caseIdentifier []byte, outFormat string) unsafe.Pointer {
	return bytesToPointer(client.CreateSignature(foldedPublicKeys, privateKeyContent, message, caseIdentifier, outFormat))
}

// VerifySignature verifies signature.
//export VerifySignature
func VerifySignature(foldedPublicKeys, signature, message, caseIdentifier []byte) int {
	return client.VerifySignature(foldedPublicKeys, signature, message, caseIdentifier)
}

// UnfoldPublicKeys separates folded public keys into array of bytes.
//export UnfoldPublicKeys
func UnfoldPublicKeys(foldedPublicKeys []byte, outFormat string) unsafe.Pointer {
	return arrayOfByteArraysToPointer(client.UnfoldPublicKeysIntoBytes(foldedPublicKeys, outFormat))
}

// PublicKeysDigest returns digest of public keys.
//export PublicKeysDigest
func PublicKeysDigest(foldedPublicKeys []byte, separator bool) unsafe.Pointer {
	return bytesToPointer(client.PublicKeysDigest(foldedPublicKeys, separator))
}

// PublicKeyXYCoordinates returns X,Y coordinates of public key.
//export PublicKeyXYCoordinates
func PublicKeyXYCoordinates(pubicKey []byte) unsafe.Pointer {
	return bytesToPointer(client.PublicKeyXYCoordinates(pubicKey))
}

// GeneratePrivateKey generates private key.
//export GeneratePrivateKey
func GeneratePrivateKey(curveName, format string) unsafe.Pointer {
	return bytesToPointer(client.GeneratePrivateKey(curveName, format))
}

// DerivePublicKey derives public keys from private.
//export DerivePublicKey
func DerivePublicKey(privateKey []byte, format string) unsafe.Pointer {
	return bytesToPointer(client.DerivePublicKey(privateKey, format))
}

func main() {}
