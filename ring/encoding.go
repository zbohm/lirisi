package ring

import (
	"bytes"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"math/big"

	etmath "github.com/ethereum/go-ethereum/common/math"
)

// ## Data structure definition

// RingSignatureProtocol DEFINITIONS ::= BEGIN
// 	Signature ::= OCTET STRING (SIZE(
// 		32 -- Image.X
// 		32 -- Image.Y
// 		32 -- C
// 		32 * n  -- n is number of S octets
// 	))
// END

// ImageToBytes returns bytes signature unique code.
func (r *Signature) ImageToBytes() (buff []byte) {
	buff = append(buff, etmath.PaddedBigBytes(r.I.X, 32)...)
	buff = append(buff, etmath.PaddedBigBytes(r.I.Y, 32)...)
	return
}

// ImageToBase64 encodes Private key image to base64.
func (r *Signature) ImageToBase64() (buff []byte) {
	image := r.ImageToBytes()
	buff = make([]byte, base64.StdEncoding.EncodedLen(len(image)))
	base64.StdEncoding.Encode(buff, image)
	return
}

// ToBytes converts signature to bytes array.
func (r *Signature) ToBytes() (data []byte) {
	// I.X + I.Y + C + S[size]
	data = append(data, r.ImageToBytes()...)
	data = append(data, etmath.PaddedBigBytes(r.C, 32)...)
	for _, s := range r.S {
		data = append(data, etmath.PaddedBigBytes(s, 32)...)
	}
	return
}

// FromBytes creates signature from bytes array.
func FromBytes(data []byte) (*Signature, error) {
	var doubleword [32]byte

	buff := bytes.NewBuffer(data)
	sig := new(Signature)
	sig.I = new(PrivKeyImage)

	// Sign Key Image
	if err := binary.Read(buff, binary.LittleEndian, &doubleword); err != nil {
		return nil, err
	}
	sig.I.X = new(big.Int).SetBytes(doubleword[:])
	if err := binary.Read(buff, binary.LittleEndian, &doubleword); err != nil {
		return nil, err
	}
	sig.I.Y = new(big.Int).SetBytes(doubleword[:])

	// Sign.C (32 bytes)
	if err := binary.Read(buff, binary.LittleEndian, &doubleword); err != nil {
		return nil, err
	}
	sig.C = new(big.Int).SetBytes(doubleword[:])

	// I.X + I.Y + C + S[size]
	size := (len(data) - (32 * 3)) / 32
	sig.S = make([]*big.Int, size)
	for i := 0; i < size; i++ {
		if err := binary.Read(buff, binary.LittleEndian, &doubleword); err != nil {
			return nil, err
		}
		sig.S[i] = new(big.Int).SetBytes(doubleword[:])
	}

	return sig, nil
}

// Marshal signature to bytes.
func (r *Signature) Marshal() ([]byte, error) {
	return asn1.Marshal(r.ToBytes())
}

// Unmarshal signature from bytes.
func Unmarshal(data []byte) (*Signature, error) {
	var i interface{}
	_, err := asn1.Unmarshal(data, &i)
	if err != nil {
		return nil, err
	}
	return FromBytes(i.([]byte))
}

// Armor Signature to hexadecimal bytes.
func (r *Signature) Armor() (dst []byte, err error) {
	src, err := r.Marshal()
	if err != nil {
		return nil, err
	}
	dst = make([]byte, base64.StdEncoding.EncodedLen(len(src)))
	base64.StdEncoding.Encode(dst, src)
	return
}

// Dearmor Signature to hexadecimal bytes.
func Dearmor(data []byte) (*Signature, error) {
	bytes := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	if _, err := base64.StdEncoding.Decode(bytes, data); err != nil {
		return nil, err
	}
	return Unmarshal(bytes)
}

// ToPEM serialize Signature to format PEM
func (r *Signature) ToPEM() ([]byte, error) {
	sign, err := r.Armor()
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type: "RING SIGNATURE",
		Headers: map[string]string{
			"KeyImage": string(r.ImageToBase64()),
		},
		Bytes: sign,
	}
	var buff []byte
	dst := bytes.NewBuffer(buff)
	if err := pem.Encode(dst, block); err != nil {
		return nil, err
	}
	return dst.Bytes(), nil
}

// FromPEM reads Signature from PEM.
func FromPEM(data []byte) (*Signature, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "RING SIGNATURE" {
		return nil, errors.New("unknown PEM type")
	}
	return Dearmor(block.Bytes)
}
