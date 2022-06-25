package kkcrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"hash"
	"io"
	"math"
	"math/big"
	"strings"
)

const byteBase = float64(8)

type PEM interface {
	PEMPrivateKey() string
	PEMPublicKey() string
}

type Public interface {
	Key() *ecdsa.PublicKey
	PEM() string
	Verify(data []byte, signature []byte, hash hash.Hash) bool
	Bytes() []byte
	Hex() string
}

type PublicKey ecdsa.PublicKey

func (k *PublicKey) Key() *ecdsa.PublicKey {
	return (*ecdsa.PublicKey)(k)
}

func (k *PublicKey) PEM() string {
	x509Encoded, _ := x509.MarshalPKIXPublicKey(k.Key())
	pemEncoded := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PUBLIC KEY",
		Bytes: x509Encoded,
	})

	return string(pemEncoded)
}

func (k *PublicKey) Verify(data []byte, signature []byte, hash hash.Hash) bool {
	keySize := int(math.Ceil(float64(k.Curve.Params().BitSize) / byteBase))
	if len(signature) != 2*keySize {
		return false
	}

	r := big.NewInt(0).SetBytes(signature[:keySize])
	s := big.NewInt(0).SetBytes(signature[keySize:])
	hasher := hash
	hasher.Write(data)
	return ecdsa.Verify((*ecdsa.PublicKey)(k), hasher.Sum(nil), r, s)

}

func (k *PublicKey) Bytes() []byte {
	keySize := int(math.Ceil(float64(k.Curve.Params().BitSize) / byteBase))
	x := make([]byte, keySize)
	ox := k.X.Bytes()
	copy(x[keySize-len(ox):], ox)
	y := make([]byte, keySize)
	oy := k.Y.Bytes()
	copy(y[keySize-len(oy):], oy)
	return append(append([]byte{0x04}, x...), y...)
}

func (k *PublicKey) Hex() string {
	return strings.ToUpper(hex.EncodeToString(k.Bytes()))
}

type Private interface {
	PEM() string
	Key() *ecdsa.PrivateKey
	Public() PublicKey
	Sign(data []byte, hash hash.Hash) []byte
	Bytes() []byte
	PrivateKeyHex() string
}

type PrivateKey ecdsa.PrivateKey

func (k *PrivateKey) PEM() string {
	x509Encoded, _ := x509.MarshalECPrivateKey(k.Key())
	pemEncoded := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: x509Encoded,
	})

	return string(pemEncoded)
}

func (k *PrivateKey) Key() *ecdsa.PrivateKey {
	return (*ecdsa.PrivateKey)(k)
}

func (k *PrivateKey) Public() PublicKey {
	return PublicKey(k.PublicKey)
}

func (k *PrivateKey) Sign(data []byte, hash hash.Hash) []byte {
	keySize := int(math.Ceil(float64(k.Curve.Params().BitSize) / byteBase))
	hash.Write(data)
	if r, s, err := ecdsa.Sign(rand.Reader, k.Key(), hash.Sum(nil)); err == nil {
		rBytes := r.Bytes()
		rBytesPadded := make([]byte, keySize)
		copy(rBytesPadded[keySize-len(rBytes):], rBytes)

		sBytes := s.Bytes()
		sBytesPadded := make([]byte, keySize)
		copy(sBytesPadded[keySize-len(sBytes):], sBytes)
		return append(rBytesPadded, sBytesPadded...)
	}

	return nil
}

func (k *PrivateKey) Bytes() []byte {
	keySize := int(math.Ceil(float64(k.Curve.Params().BitSize) / byteBase))
	d := make([]byte, keySize)
	od := k.D.Bytes()
	copy(d[keySize-len(od):], od)
	return d
}

func (k *PrivateKey) PrivateKeyHex() string {
	return strings.ToUpper(hex.EncodeToString(k.Bytes()))
}

type ES struct {
	Private *PrivateKey
	HashId  crypto.Hash
}

func (e *ES) Hash() hash.Hash {
	return e.HashId.New()
}

func (e *ES) Sign(data []byte) []byte {
	return e.Private.Sign(data, e.Hash())
}

func (e *ES) Verify(data []byte, signature []byte) bool {
	return e.PublicKey().Verify(data, signature, e.Hash())
}

func (e *ES) X() *big.Int {
	return e.Private.X
}

func (e *ES) Y() *big.Int {
	return e.Private.Y
}

func (e *ES) D() *big.Int {
	return e.Private.D
}

func (e *ES) Curve() EllipticCurve {
	return e.Private.Curve
}

func (e *ES) PrivateKey() *PrivateKey {
	return e.Private
}

func (e *ES) PublicKey() *PublicKey {
	return (*PublicKey)(&e.Private.PublicKey)
}

func NewRawES(curve EllipticCurve, rand io.Reader, hash crypto.Hash) *ES {
	es := &ES{
		HashId: hash,
	}

	if private, err := ecdsa.GenerateKey(curve, rand); err != nil {
		panic(err)
	} else {
		es.Private = (*PrivateKey)(private)
	}

	return es

}

func NewES(curve EllipticCurve) *ES {
	if curve == nil {
		return nil
	}

	switch curve.Params().BitSize {
	case 256:
		return NewRawES(curve, rand.Reader, crypto.SHA256)
	case 384:
		return NewRawES(curve, rand.Reader, crypto.SHA384)
	case 521:
		return NewRawES(curve, rand.Reader, crypto.SHA512)
	}

	return nil
}

func NewES256() *ES {
	return NewES(P256())
}

func NewES384() *ES {
	return NewES(P384())
}

func NewES512() *ES {
	return NewES(P521())
}
