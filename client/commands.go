package client

import (
	"bufio"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/zbohm/lirisi/ring"
)

// CreatePrivateKey creates private key and print it on stdout or save it into the filename.
func CreatePrivateKey(output string) {
	privKey, err := crypto.GenerateKey()
	if err != nil {
		panic(err)
	}
	if output == "" {
		fmt.Println(hex.EncodeToString(crypto.FromECDSA(privKey)))
	} else {
		if err := crypto.SaveECDSA(output, privKey); err != nil {
			panic(err)
		}
	}
}

// ExtractPublicKey from private key and encode it to base64.
func ExtractPublicKey(output, privkeyFilename string) {
	privKey, err := crypto.LoadECDSA(privkeyFilename)
	if err != nil {
		panic(err)
	}
	pubKey := privKey.Public().(*ecdsa.PublicKey)
	data := base64.StdEncoding.EncodeToString(crypto.FromECDSAPub(pubKey))
	bytes := append([]byte(data), '\n')
	if output == "" {
		fmt.Println(data)
	} else {
		ioutil.WriteFile(output, bytes, 0600)
	}
}

// CreateTestingRing creates the list of public keys for testing purposes.
func CreateTestingRing(output string, size int) {
	var file *os.File
	var err error
	if output != "" {
		file, err = os.OpenFile(output, os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatal(err)
		}
	}
	for i := 0; i < size; i++ {
		privkey, err := crypto.GenerateKey()
		if err != nil {
			log.Fatal(err)
		}
		pubKey := privkey.Public().(*ecdsa.PublicKey)
		data := base64.StdEncoding.EncodeToString(crypto.FromECDSAPub(pubKey))
		if output == "" {
			fmt.Println(data)
		} else {
			if _, err = file.Write(append([]byte(data), '\n')); err != nil {
				log.Fatal(err)
			}

		}
	}
	if output != "" {
		file.Close()
	}
}

func loadRingPubKeys(ringFilename string) ring.PublicKeysList {
	// Load public keys
	inFile, err := os.Open(ringFilename)
	if err != nil {
		log.Fatal(err)
	}
	defer inFile.Close()
	pubList := make(ring.PublicKeysList, 0)
	scanner := bufio.NewScanner(inFile)
	for scanner.Scan() {
		line := scanner.Text()
		data, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			log.Fatal(err)
		}
		pubKey, err := crypto.UnmarshalPubkey(data)
		if err != nil {
			log.Fatal(err)
		}
		pubList = append(pubList, pubKey)
	}
	return pubList
}

// CreateSignature creates the signature and save it to PEM.
func CreateSignature(output, message, ringFilename, privateFilename string) {
	// Load private key
	privKey, err := crypto.LoadECDSA(privateFilename)
	if err != nil {
		log.Fatal(err)
	}
	// Load public keys
	ringPubList := loadRingPubKeys(ringFilename)
	// Make signature
	sign, err := ring.CreateSign([]byte(message), ringPubList, privKey)
	if err != nil {
		log.Fatal(err)
	}
	pem, err := sign.ToPEM()
	if output == "" {
		fmt.Println(string(pem))
	} else {
		ioutil.WriteFile(output, pem, 0600)
	}
}

// VerifySignature verifies signature for message and keys ring.
func VerifySignature(output, message, ringFilename, signatureFilename string) {
	// Load signature
	pem, err := ioutil.ReadFile(signatureFilename)
	if err != nil {
		log.Fatal(err)
	}
	sign, err := ring.FromPEM(pem)
	if err != nil {
		log.Fatal(err)
	}
	// Load public keys
	ringPubList := loadRingPubKeys(ringFilename)
	// Verify signature
	if ring.VerifySign(sign, []byte(message), ringPubList) {
		if output == "" {
			fmt.Println("SUCCESS")
		} else {
			ioutil.WriteFile(output, []byte("SUCCESS\n"), 0600)
		}
	} else {
		if output == "" {
			log.Fatal("ERROR")
		} else {
			ioutil.WriteFile(output, []byte("ERROR\n"), 0600)
			os.Exit(1)
		}
	}
}
