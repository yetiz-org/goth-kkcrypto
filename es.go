package kkcrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"hash"
	"io"
	"math"
	"math/big"
)

const byteBase = float64(8)

type PEM interface {
	PEMPrivateKey() string
	PEMPublicKey() string
}

type ES interface {
	X() *big.Int
	Y() *big.Int
	D() *big.Int
	Curve() EllipticCurve
	PrivateKey() *ecdsa.PrivateKey
	PublicKey() *ecdsa.PublicKey
	Hash() hash.Hash
	Sign(data []byte) []byte
	Verify(data []byte, signature []byte) bool
	PEM
}

type es struct {
	private *ecdsa.PrivateKey
	hash    crypto.Hash
}

func (e *es) Hash() hash.Hash {
	return e.hash.New()
}

func (e *es) Sign(data []byte) []byte {
	hasher := e.Hash()
	hasher.Write(data)
	if r, s, err := ecdsa.Sign(rand.Reader, e.PrivateKey(), hasher.Sum(nil)); err == nil {
		keySize := int(math.Ceil(float64(e.PrivateKey().Curve.Params().BitSize) / byteBase))
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

func (e *es) Verify(data []byte, signature []byte) bool {
	keySize := int(math.Ceil(float64(e.PrivateKey().Curve.Params().BitSize) / byteBase))
	if len(signature) != 2*keySize {
		return false
	}

	r := big.NewInt(0).SetBytes(signature[:keySize])
	s := big.NewInt(0).SetBytes(signature[keySize:])
	hasher := e.Hash()
	hasher.Write(data)
	return ecdsa.Verify(e.PublicKey(), hasher.Sum(nil), r, s)
}

func (e *es) X() *big.Int {
	return e.private.X
}

func (e *es) Y() *big.Int {
	return e.private.Y
}

func (e *es) D() *big.Int {
	return e.private.D
}

func (e *es) Curve() EllipticCurve {
	return e.private.Curve
}

func (e *es) PrivateKey() *ecdsa.PrivateKey {
	return e.private
}

func (e *es) PublicKey() *ecdsa.PublicKey {
	return &e.private.PublicKey
}

func (e *es) PEMPrivateKey() string {
	x509Encoded, _ := x509.MarshalECPrivateKey(e.PrivateKey())
	pemEncoded := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: x509Encoded,
	})

	return string(pemEncoded)
}

func (e *es) PEMPublicKey() string {
	x509Encoded, _ := x509.MarshalPKIXPublicKey(e.PublicKey())
	pemEncoded := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PUBLIC KEY",
		Bytes: x509Encoded,
	})

	return string(pemEncoded)
}

func NewRawES(curve EllipticCurve, rand io.Reader, hash crypto.Hash) ES {
	es := &es{
		hash: hash,
	}

	if private, err := ecdsa.GenerateKey(curve, rand); err != nil {
		panic(err)
	} else {
		es.private = private
	}

	return es

}

func NewES(curve EllipticCurve) ES {
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

func NewES256() ES {
	return NewES(P256())
}

func NewES384() ES {
	return NewES(P384())
}

func NewES512() ES {
	return NewES(P521())
}
