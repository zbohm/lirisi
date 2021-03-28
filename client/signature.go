package client

import (
	"bytes"
	"encoding/asn1"
	"encoding/pem"
	"strconv"

	"github.com/zbohm/lirisi/ring"
)

// CreateSignature creates signature and encode it into DER or PEM.
func CreateSignature(foldedPublicKeys, privateKeyContent, message, caseIdentifier []byte, outFormat string) (int, []byte) {

	content := []byte{}

	status, publicKeys, foldedKeys := UnfoldPublicKeysContent(foldedPublicKeys)
	if status != ring.Success {
		return status, content
	}
	curveType, ok := ring.GetCurve(foldedKeys.CurveOID)
	if !ok {
		return ring.UnexpectedCurveType, content
	}
	hashFnc, ok := ring.GetHasher(foldedKeys.HasherOID)
	if !ok {
		return ring.UnexpectedHashType, content
	}
	status, privateKey := ParsePrivateKey(privateKeyContent)
	if status != ring.Success {
		return status, content
	}
	status, signature := ring.Create(curveType, hashFnc, privateKey, publicKeys, message, caseIdentifier)
	if status != ring.Success {
		return status, content
	}

	if outFormat == "PEM" {
		status, content = EncodeSignarureToPEM(signature)
		if status != ring.Success {
			return status, content
		}
	} else {
		status, content = EncodeSignarureToDER(signature)
		if status != ring.Success {
			return status, content
		}
	}
	return ring.Success, content
}

// EncodeSignarureToDER encodes signature to DER.
func EncodeSignarureToDER(signature *ring.Signature) (int, []byte) {
	content, err := asn1.Marshal(*signature)
	if err != nil {
		return ring.Asn1MarshalFailed, content
	}
	return ring.Success, content
}

// EncodeSignarureToPEM encodes signature to PEM.
func EncodeSignarureToPEM(signature *ring.Signature) (int, []byte) {
	status, contentDer := EncodeSignarureToDER(signature)
	if status != ring.Success {
		return status, contentDer
	}
	curveType, _ := ring.GetCurve(signature.CurveOID)
	hashFnc, _ := ring.GetHasher(signature.HasherOID)

	block := &pem.Block{
		Type: "RING SIGNATURE",
		Headers: map[string]string{
			"Origin":       ring.Origin,
			"CurveName":    ring.GetCurveName(curveType()),
			"CurveOID":     signature.CurveOID.String(),
			"HasherOID":    signature.HasherOID.String(),
			"HasherName":   ring.GetHasherName(hashFnc),
			"NumberOfKeys": strconv.Itoa(len(signature.Signatures)),
			// "KeyImage":     FormatDigest(hex.EncodeToString(signature.KeyImage.Bytes())),
			"KeyImage": formatKeyImage(signature.KeyImage),
		},
		Bytes: contentDer,
	}
	var buff bytes.Buffer
	if err := pem.Encode(&buff, block); err != nil {
		return ring.EncodePEMFailed, contentDer
	}
	return ring.Success, buff.Bytes()
}

// VerifySignature verifies signature.
func VerifySignature(foldedPublicKeys, signature, message, caseIdentifier []byte) int {
	status, sign := ParseSignature(signature)
	if status != ring.Success {
		return status
	}
	status, publicKeys, _ := UnfoldPublicKeysContent(foldedPublicKeys)
	if status != ring.Success {
		return status
	}
	return ring.Verify(&sign, publicKeys, message, caseIdentifier)
}
