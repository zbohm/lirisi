package client

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"

	"github.com/zbohm/lirisi/ring"
	"github.com/zbohm/lirisi/x509ec"
)

// ReadFromFileOrStdin reads from file or stdin.
func ReadFromFileOrStdin(sourceName string) []byte {
	var content []byte
	var err error

	if sourceName == "-" {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			content = append(content, scanner.Bytes()...)
			content = append(content, Enter...)
		}
		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}
	} else {
		content, err = ioutil.ReadFile(sourceName)
		if err != nil {
			log.Fatal(err)
		}
	}
	return content
}

// WriteOutput writes content to the output.
func WriteOutput(output string, content []byte) {
	if output == "" {
		fmt.Printf("%s", content)
	} else {
		err := ioutil.WriteFile(output, content, 0644)
		if err != nil {
			log.Fatal(err)
		}
	}
}

// ParseSignature parses signature in format PEM or DER.
func ParseSignature(content []byte) (int, ring.Signature) {
	sign := ring.Signature{}
	if matched, _ := regexp.Match(`-+BEGIN RING SIGNATURE`, content); matched {
		block, _ := pem.Decode(content)
		if block == nil {
			return ring.DecodePEMFailure, sign
		}
		content = block.Bytes
	}
	rest, err := asn1.Unmarshal(content, &sign)
	if err != nil {
		return ring.Asn1UnmarshalFailed, sign
	}
	if len(rest) > 0 {
		return ring.UnexpectedRestOfSignature, sign
	}
	return ring.Success, sign
}

// ParsePrivateKey parses private key from bytes.
func ParsePrivateKey(content []byte) (int, *ecdsa.PrivateKey) {
	if matched, _ := regexp.Match(`-+BEGIN EC PRIVATE`, content); matched {
		block, _ := pem.Decode(content)
		if block == nil {
			return ring.DecodePEMFailure, nil
		}
		content = block.Bytes
	}
	privateKey, err := x509ec.ParseECPrivateKey(content)
	if err != nil {
		return ring.ParseECPrivateKeyFailure, nil
	}
	return ring.Success, privateKey
}

// ReadMessage reads message from the file or use param as a message.
func ReadMessage(messageOrFilename string) []byte {
	if _, err := os.Stat(messageOrFilename); os.IsNotExist(err) {
		return []byte(messageOrFilename)
	}
	message, err := ioutil.ReadFile(messageOrFilename)
	if err != nil {
		log.Fatal(err)
	}
	return message
}

// FormatDigest makes digest more human readable: 'c29da7' -> 'c2:9d:a7'
// openssl dgst -c -sha3-256 $curve-digests.txt | cut -d ' ' -f2
func FormatDigest(text string) string {
	var buffer bytes.Buffer
	var separator byte = ':'

	for i := 0; i < len(text); i++ {
		if i > 0 && i%2 == 0 {
			if err := buffer.WriteByte(separator); err != nil {
				log.Fatal(err)
			}
		}
		if err := buffer.WriteByte(text[i]); err != nil {
			log.Fatal(err)
		}
	}
	return buffer.String()
}

// LoadFolder read all files from the folder.
func LoadFolder(folder string) [][]byte {
	var contents [][]byte

	files, err := ioutil.ReadDir(folder)
	if err != nil {
		log.Fatal(err)
	}
	for _, file := range files {
		name := file.Name()
		content, err := ioutil.ReadFile(filepath.Join(folder, name))
		if err != nil {
			log.Fatal(err)
		}
		contents = append(contents, content)
	}
	return contents
}
