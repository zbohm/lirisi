package client

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/pem"

	"github.com/zbohm/lirisi/ring"
	"github.com/zbohm/lirisi/x509ec"
)

// GeneratePrivateKey generate private key and encode it to the required format.
func GeneratePrivateKey(curveName, format string) (int, []byte) {

	curveType, ok := ring.CurveCodes[curveName]
	if !ok {
		return ring.UnexpectedCurveType, []byte{}
	}
	privateKey, err := ecdsa.GenerateKey(curveType(), rand.Reader)
	if err != nil {
		return ring.CreateKeyFailed, []byte{}
	}
	content, err := x509ec.MarshalECPrivateKey(privateKey)
	if err != nil {
		return ring.MarshalKeyFailed, []byte{}
	}
	if format == "PEM" {
		block := &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: content,
		}
		var buff bytes.Buffer
		if err := pem.Encode(&buff, block); err != nil {
			return ring.EncodePEMFailed, content
		}
		content = buff.Bytes()
	}
	return ring.Success, content
}
