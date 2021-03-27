// Subset of crypto/x509 for supporting more elliptic curves.
// https://golang.org/src/crypto/x509/pkcs8.go

package x509ec

import (
	"crypto/x509/pkix"
)

// pkcs8 reflects an ASN.1, PKCS #8 PrivateKey. See
// ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-8/pkcs-8v1_2.asn
// and RFC 5208.
type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// optional attributes omitted.
}
