package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"hash"
	"log"

	"github.com/zbohm/lirisi/client"
	"github.com/zbohm/lirisi/ring"
)

func encodePublicKeyToDer(key *ecdsa.PublicKey) []byte {
	derKey, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		log.Fatal(err)
	}
	return derKey
}

// Auxiliary function for creating public keys.
func createPublicKeyList(curve elliptic.Curve, size int) []*ecdsa.PublicKey {
	publicKeys := make([]*ecdsa.PublicKey, size)
	for i := 0; i < size; i++ {
		privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		publicKeys[i] = privateKey.Public().(*ecdsa.PublicKey)
	}
	return publicKeys
}

func createPrivateAndPublicKeyExample() {
	// Create private key
	status, privateKey := client.GeneratePrivateKey("prime256v1", "PEM")
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("%s", privateKey)
	// Create public key.
	status, publicKey := client.DerivePublicKey(privateKey, "PEM")
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("%s", publicKey)
}

func baseExample(
	curveType func() elliptic.Curve,
	hashFnc func() hash.Hash,
	privateKey *ecdsa.PrivateKey,
	publicKeys []*ecdsa.PublicKey,
	message, caseIdentifier []byte,
) ([]byte, []byte) {
	// Make signature.
	status, signature := ring.Create(curveType, hashFnc, privateKey, publicKeys, message, caseIdentifier)
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}

	// Verify signature.
	status = ring.Verify(signature, publicKeys, message, caseIdentifier)
	if status == ring.Success {
		fmt.Println("Signature verified OK")
	} else {
		fmt.Println("Signature verification Failure")
	}

	// Encode signature to format DER.
	status, signatureDer := client.EncodeSignarureToDER(signature)
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("Signature in DER:\n%s\n", hex.Dump(signatureDer))

	// Encode signature to format PEM.
	status, signaturePem := client.EncodeSignarureToPEM(signature)
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("Signature in PEM:\n%s\n", signaturePem)
	return signatureDer, signaturePem
}

func foldedKeysExample(privateKey *ecdsa.PrivateKey, foldedPublicKeys, signatureDer, signaturePem, message, caseIdentifier []byte) {
	// Verify signature in DER.
	status := client.VerifySignature(foldedPublicKeys, signatureDer, message, caseIdentifier)
	if status == ring.Success {
		fmt.Println("Signature in DER: Verified OK")
	} else {
		fmt.Println("Signature in DER: Verification Failure")
	}
	// Verify signature in PEM.
	status = client.VerifySignature(foldedPublicKeys, signaturePem, message, caseIdentifier)
	if status == ring.Success {
		fmt.Println("Signature in PEM: Verified OK")
	} else {
		fmt.Println("Signature in PEM: Verification Failure")
	}

	// Encode private key to DER.
	privateKeyDer, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		log.Fatal(err)
	}
	// Make first signature in format DER.
	status, signatureDer = client.CreateSignature(foldedPublicKeys, privateKeyDer, message, caseIdentifier, "DER")
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("Signature in DER Nr.2:\n\n%s\n", hex.Dump(signatureDer))
	// Verify signature in DER.
	status = client.VerifySignature(foldedPublicKeys, signatureDer, message, caseIdentifier)
	if status == ring.Success {
		fmt.Println("Signature in DER Nr.2: Verified OK")
	} else {
		fmt.Println("Signature in DER Nr.2: Verification Failure")
	}

	// Make second signature in format PEM.
	status, signaturePem = client.CreateSignature(foldedPublicKeys, privateKeyDer, message, caseIdentifier, "PEM")
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("Signature in PEM:\n\n%s\n", signaturePem)
	// Verify signature in PEM.
	status = client.VerifySignature(foldedPublicKeys, signaturePem, message, caseIdentifier)
	if status == ring.Success {
		fmt.Println("Signature in PEM Nr.2: Verified OK")
	} else {
		fmt.Println("Signature in PEM Nr.2: Verification Failure")
	}
	fmt.Println()
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Choose curve type.
	curveType := elliptic.P256
	// Choose hash type.
	hashName := "sha3-256"
	hashFnc, ok := ring.HashCodes[hashName]
	if !ok {
		log.Fatal(ring.UnexpectedHashType)
	}

	createPrivateAndPublicKeyExample()

	// Creating public keys as a simulation of keys supplied by other signers.
	publicKeys := createPublicKeyList(curveType(), 9)

	// Create your private key.
	privateKey, err := ecdsa.GenerateKey(curveType(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	// Add your public key to other public keys.
	publicKey := privateKey.Public().(*ecdsa.PublicKey)
	publicKeys = append(publicKeys, publicKey)

	status, coordinates := client.PublicKeyXYCoordinates(encodePublicKeyToDer(publicKey))
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("Coordinates of public key:\n%s\n", hex.Dump(coordinates))

	message := []byte("Hello world!")
	caseIdentifier := []byte("Round Nr.1")

	signatureDer, signaturePem := baseExample(curveType, hashFnc, privateKey, publicKeys, message, caseIdentifier)

	// Encode public keys to DER.
	publicKeysDer := [][]byte{}

	for _, key := range publicKeys {
		publicKeysDer = append(publicKeysDer, encodePublicKeyToDer(key))
	}

	// Create the content of file with public keys.
	status, foldedPublicKeys := client.FoldPublicKeys(publicKeysDer, hashName, "DER", "notsort")
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("Public keys in DER:\n%s\n", hex.Dump(foldedPublicKeys))
	// Display fingerprint of public keys in format PEM.
	status, digest := client.PublicKeysDigest(foldedPublicKeys, true)
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("Public keys digest: %s\n\n", digest)

	// Display fingerprint of public keys in format DER.
	status, foldedPublicKeysPEM := client.FoldPublicKeys(publicKeysDer, hashName, "PEM", "notsort")
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("Keys from DER:\n%s\n", foldedPublicKeysPEM)

	foldedKeysExample(privateKey, foldedPublicKeys, signatureDer, signaturePem, message, caseIdentifier)

	// Decompose folded public keys into files.
	status, unfoldedPublicKeys := client.UnfoldPublicKeysIntoBytes(foldedPublicKeys, "PEM")
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	for i, pubKey := range unfoldedPublicKeys {
		fmt.Printf("%d. public key:\n%s\n", i+1, pubKey)
	}
}
