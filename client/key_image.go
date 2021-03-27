package client

import (
	"bytes"
	"encoding/hex"
	"log"

	"github.com/zbohm/lirisi/ring"
)

// SignatureKeyImage outputs signature key image.
func SignatureKeyImage(body []byte, separator bool) (int, []byte) {
	status, sign := ParseSignature(body)
	if status != ring.Success {
		return status, []byte(ring.ErrorMessages[status])
	}
	digest := sign.KeyImage.Bytes()
	content := hex.EncodeToString(digest)
	if separator {
		content = FormatDigest(content)
	}
	return ring.Success, []byte(content)
}

// formatKeyImage into more human readable form
func formatKeyImage(keyImage ring.PointData) string {
	line := len(keyImage.X) / 2
	buf := bytes.NewBufferString("")
	if _, err := buf.WriteString("\n  " + FormatDigest(hex.EncodeToString(keyImage.X[:line]))); err != nil {
		log.Fatal(err)
	}
	if _, err := buf.WriteString("\n  " + FormatDigest(hex.EncodeToString(keyImage.X[line:]))); err != nil {
		log.Fatal(err)
	}
	if _, err := buf.WriteString("\n  " + FormatDigest(hex.EncodeToString(keyImage.Y[:line]))); err != nil {
		log.Fatal(err)
	}
	if _, err := buf.WriteString("\n  " + FormatDigest(hex.EncodeToString(keyImage.Y[line:]))); err != nil {
		log.Fatal(err)
	}
	return buf.String()
}
