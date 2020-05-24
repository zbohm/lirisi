package client

import (
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
)

// CreatePrivateKey creates private key and print it on stdout or save it into the filename.
func CreatePrivateKey(filename string) {
	privKey, err := crypto.GenerateKey()
	if err != nil {
		panic(err)
	}
	if filename == "" {
		fmt.Println(hex.EncodeToString(crypto.FromECDSA(privKey)))
	} else {
		if err := crypto.SaveECDSA(filename, privKey); err != nil {
			panic(err)
		}
	}
}
