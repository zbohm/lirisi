package client

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"hash"
	"math/big"
	"regexp"
	"sort"
	"strconv"

	"github.com/zbohm/lirisi/ring"
	"github.com/zbohm/lirisi/x509ec"
)

// IdentKey holds filename, digest (hash) of file, instance of public key.
type IdentKey struct {
	digest string
	key    *ecdsa.PublicKey
}

// HashIdentKey contains the salted hash of public key file and IdentKey.
type HashIdentKey struct {
	hash string
	pub  IdentKey
}

// Enter asci character LF.
var Enter = []byte("\n")

// FoldPublicKeys create sequence of public keys coordinates.
func FoldPublicKeys(pubKeysContent [][]byte, hashName, format, order string) (int, []byte) {

	var content, keysDigest []byte
	var curve elliptic.Curve
	var publicKeys []HashIdentKey
	var status int

	hashFnc, ok := ring.HashCodes[hashName]
	if !ok {
		return ring.UnexpectedHashType, content
	}
	hasherOID, status := ring.GetHasherOID(hashFnc)
	if status != ring.Success {
		return status, content
	}
	status, publicKeys, keysDigest = decodePublicKeys(pubKeysContent, hashFnc)
	if status != ring.Success {
		return status, content
	}
	if order == "hashes" {
		status, publicKeys, keysDigest = sortKeysByHashes(publicKeys, hashFnc)
		if status != ring.Success {
			return status, content
		}
	}
	pointSeq := ring.FoldedPublicKeys{Name: ring.Origin + " Public keys", HasherOID: hasherOID, Digest: keysDigest}
	compress := true

	for i, item := range publicKeys {
		if i == 0 {
			curve = item.pub.key.Curve
			curveOID, status := ring.GetCurveOIDForCurve(item.pub.key.Curve)
			if status != ring.Success {
				return status, content
			}
			pointSeq.CurveOID = curveOID
			// Uncompress does not work for these curves:
			//	- secp256k1
			// 	- brainpoolP256r1
			//  - brainpoolP384r1
			//	- brainpoolP512r1
			oid := curveOID.String()
			if oid == "1.3.132.0.10" || oid == "1.3.36.3.3.2.8.1.1.7" || oid == "1.3.36.3.3.2.8.1.1.11" || oid == "1.3.36.3.3.2.8.1.1.13" {
				compress = false
			}
		} else {
			if item.pub.key.Curve != curve {
				return ring.UnexpectedCurveType, content
			}
		}
		if compress {
			pointSeq.Keys = append(pointSeq.Keys, elliptic.MarshalCompressed(curve, item.pub.key.X, item.pub.key.Y))
		} else {
			pointSeq.Keys = append(pointSeq.Keys, elliptic.Marshal(curve, item.pub.key.X, item.pub.key.Y))
		}
	}
	return encodeFoldedPublicKeys(curve, pointSeq, publicKeys, keysDigest, hashName, format)
}

func encodeFoldedPublicKeys(
	curve elliptic.Curve,
	pointSeq ring.FoldedPublicKeys,
	publicKeys []HashIdentKey,
	keysDigest []byte,
	hashName,
	format string,
) (int, []byte) {
	content, err := asn1.Marshal(pointSeq)
	if err != nil {
		return ring.Asn1MarshalFailed, content
	}
	if format == "PEM" {
		block := &pem.Block{
			Type: "FOLDED PUBLIC KEYS",
			Headers: map[string]string{
				"Origin":       ring.Origin,
				"CurveName":    ring.GetCurveName(curve),
				"CurveOID":     pointSeq.CurveOID.String(),
				"HasherOID":    pointSeq.HasherOID.String(),
				"HasherName":   hashName,
				"NumberOfKeys": strconv.Itoa(len(publicKeys)),
				"Digest":       FormatDigest(hex.EncodeToString(keysDigest)),
			},
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

// UnfoldPublicKeysContent restore public keys from sequence.
func UnfoldPublicKeysContent(content []byte) (int, []*ecdsa.PublicKey, ring.FoldedPublicKeys) {

	foldedKeys := ring.FoldedPublicKeys{}

	if matched, _ := regexp.Match(`-+BEGIN FOLDED PUBLIC KEYS`, content); matched {
		block, _ := pem.Decode(content)
		if block == nil {
			return ring.DecodePEMFailure, nil, foldedKeys
		}
		content = block.Bytes
	}

	rest, err := asn1.Unmarshal(content, &foldedKeys)
	if err != nil {
		return ring.Asn1UnmarshalFailed, nil, foldedKeys
	}
	if len(rest) > 0 {
		// x509: trailing data after ASN.1 of public-key
		return ring.UnexpectedRestOfSignature, nil, foldedKeys
	}
	curveType, success := ring.GetCurve(foldedKeys.CurveOID)
	if !success {
		return ring.OIDCurveNotFound, nil, foldedKeys
	}
	curve := curveType()
	publicKeys := make([]*ecdsa.PublicKey, len(foldedKeys.Keys))

	var x, y *big.Int

	for i, buff := range foldedKeys.Keys {
		if buff[0] == 4 {
			x, y = elliptic.Unmarshal(curve, buff)
		} else {
			x, y = elliptic.UnmarshalCompressed(curve, buff)
		}
		if x == nil || y == nil {
			return ring.NilPointCoordinates, nil, foldedKeys
		}
		if !curve.IsOnCurve(x, y) {
			return ring.InvalidPointCoordinates, nil, foldedKeys
		}
		publicKeys[i] = &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	}
	return ring.Success, publicKeys, foldedKeys
}

// UnfoldPublicKeysIntoBytes restore public keys from sequence.
func UnfoldPublicKeysIntoBytes(foldedPublicKeys []byte, outFormat string) (int, [][]byte) {
	var unfoldedPublicKeys [][]byte

	status, publicKeys, _ := UnfoldPublicKeysContent(foldedPublicKeys)
	if status != ring.Success {
		return status, unfoldedPublicKeys
	}
	for _, pub := range publicKeys {
		content, err := x509ec.MarshalPKIXPublicKey(pub)
		if err != nil {
			return ring.MarshalPKIXPublicKeyFailed, unfoldedPublicKeys
		}
		if outFormat == "PEM" {
			block := &pem.Block{Type: "PUBLIC KEY", Bytes: content}
			buff := bytes.NewBuffer(make([]byte, 0))
			if err := pem.Encode(buff, block); err != nil {
				return ring.EncodePEMFailed, unfoldedPublicKeys
			}
			unfoldedPublicKeys = append(unfoldedPublicKeys, buff.Bytes())
		} else {
			unfoldedPublicKeys = append(unfoldedPublicKeys, content)
		}
	}
	return ring.Success, unfoldedPublicKeys
}

func getXYCoordinates(key *ecdsa.PublicKey) []byte {
	buff := []byte{0x04} // Uncompressed form.
	buff = append(buff, key.X.Bytes()...)
	buff = append(buff, key.Y.Bytes()...)
	return buff
}

// PublicKeyXYCoordinates outputs public key coordinates X, Y.
func PublicKeyXYCoordinates(pubicKey []byte) (int, []byte) {
	if matched, _ := regexp.Match(`-+BEGIN PUBLIC KEY`, pubicKey); matched {
		block, _ := pem.Decode(pubicKey)
		if block == nil {
			return ring.DecodePEMFailure, []byte{}
		}
		pubicKey = block.Bytes
	}
	pub, err := x509ec.ParsePKIXPublicKey(pubicKey)
	if err != nil {
		return ring.ParsePKIXPublicKeyFailed, []byte{}
	}
	return ring.Success, getXYCoordinates(pub.(*ecdsa.PublicKey))
}

func decodePublicKeys(pubKeysContent [][]byte, hasher func() hash.Hash) (int, []HashIdentKey, []byte) {
	identKeys := []HashIdentKey{}
	fc := ring.FactoryContext{Hasher: hasher}
	digests := make([]byte, 0)
	var hash string
	var block *pem.Block

	isPEM := regexp.MustCompile(`-+BEGIN PUBLIC KEY`)

	for _, content := range pubKeysContent {
		if isPEM.Match(content) {
			block, _ = pem.Decode(content)
			if block == nil {
				return ring.DecodePEMFailure, identKeys, []byte{}
			}
			content = block.Bytes
		}
		pub, err := x509ec.ParsePKIXPublicKey(content)
		if err != nil {
			return ring.ParsePKIXPublicKeyFailed, identKeys, []byte{}
		}
		hash = hex.EncodeToString(fc.MakeDigest(getXYCoordinates(pub.(*ecdsa.PublicKey))))
		digests = append(digests, hash...)
		digests = append(digests, Enter...)

		hidk := HashIdentKey{pub: IdentKey{
			digest: hash,
			key:    pub.(*ecdsa.PublicKey),
		}}
		identKeys = append(identKeys, hidk)
	}
	return ring.Success, identKeys, fc.MakeDigest(digests)
}

func sortKeysByHashes(publicKeys []HashIdentKey, hashFnc func() hash.Hash) (int, []HashIdentKey, []byte) {

	sortedPublicKeys := []HashIdentKey{}

	fc := ring.FactoryContext{Hasher: hashFnc}

	// Sort keys by their hashes
	sort.Slice(publicKeys, func(i, j int) bool { return publicKeys[i].pub.digest < publicKeys[j].pub.digest })
	digestSum := hex.EncodeToString(fc.MakeDigest(buildDigest(publicKeys)))

	// Make digests with digestSum as a salt:
	for _, item := range publicKeys {
		item := HashIdentKey{
			hash: hex.EncodeToString(fc.MakeDigest([]byte(digestSum + item.pub.digest))),
			pub:  item.pub,
		}
		sortedPublicKeys = append(sortedPublicKeys, item)
	}
	// Sort by hashes with fingerprint as a salt
	sort.Slice(sortedPublicKeys, func(i, j int) bool { return sortedPublicKeys[i].hash < sortedPublicKeys[j].hash })
	digests := make([]byte, 0)
	for _, pk := range sortedPublicKeys {
		digests = append(digests, pk.pub.digest...)
		digests = append(digests, Enter...)
	}
	return ring.Success, sortedPublicKeys, fc.MakeDigest(digests)
}

// PublicKeysDigest outputs public keys digest.
func PublicKeysDigest(foldedPublicKeys []byte, separator bool) (int, []byte) {
	var digest []byte

	status, publicKeys, foldedKeys := UnfoldPublicKeysContent(foldedPublicKeys)
	if status != ring.Success {
		return status, digest
	}
	hashFnc, ok := ring.GetHasher(foldedKeys.HasherOID)
	if !ok {
		return ring.UnexpectedHashType, digest
	}
	fc := ring.FactoryContext{Hasher: hashFnc}
	digests := make([]byte, 0)

	for _, pub := range publicKeys {
		hash := hex.EncodeToString(fc.MakeDigest(getXYCoordinates(pub)))
		digests = append(digests, hash...)
		digests = append(digests, Enter...)
	}
	content := hex.EncodeToString(fc.MakeDigest(digests))
	if separator {
		content = FormatDigest(content)
	}
	return ring.Success, []byte(content)
}

func buildDigest(hk []HashIdentKey) []byte {
	digests := make([]byte, 0)
	for _, item := range hk {
		digests = append(digests, item.pub.digest...)
		digests = append(digests, Enter...)
	}
	return digests
}

// DerivePublicKey derives public key from private.
func DerivePublicKey(encodedPrivateKey []byte, format string) (int, []byte) {
	status, privateKey := ParsePrivateKey(encodedPrivateKey)
	if status != ring.Success {
		return status, []byte{}
	}
	publicKey := privateKey.Public().(*ecdsa.PublicKey)
	content, err := x509ec.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return ring.MarshalPKIXPublicKeyFailed, content
	}
	if format == "PEM" {
		block := &pem.Block{Type: "PUBLIC KEY", Bytes: content}
		buff := bytes.NewBuffer(make([]byte, 0))
		if err := pem.Encode(buff, block); err != nil {
			return ring.EncodePEMFailed, content
		}
		content = buff.Bytes()
	}
	return ring.Success, content
}
