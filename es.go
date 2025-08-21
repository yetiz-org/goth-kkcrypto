package kkcrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"hash"
	"io"
	"math"
	"math/big"
)

const (
	byteBase = float64(8)
	
	// Public key point format constants
	UncompressedPointFormat = 0x04 // Uncompressed public key format
	CompressedEvenYFormat   = 0x02 // Compressed format with even Y coordinate
	CompressedOddYFormat    = 0x03 // Compressed format with odd Y coordinate
)

// PEM interface defines methods for encoding cryptographic keys in PEM format.
// PEM (Privacy Enhanced Mail) is a base64 encoding format for cryptographic keys and certificates.
type PEM interface {
	// PEMPrivateKey returns the private key encoded in PEM format
	PEMPrivateKey() string
	// PEMPublicKey returns the public key encoded in PEM format
	PEMPublicKey() string
}

// Public interface defines methods for ECDSA public key operations.
// It provides functionality for signature verification, key encoding, and format conversion.
type Public interface {
	// Key returns the underlying ecdsa.PublicKey
	Key() *ecdsa.PublicKey
	// PEM returns the public key encoded in PEM format
	PEM() string
	// Verify verifies a signature against data using the specified hash algorithm
	Verify(data []byte, signature []byte, hash hash.Hash) bool
	// Bytes returns the public key as uncompressed point bytes
	Bytes() []byte
	// Hex returns the public key as uppercase hexadecimal string
	Hex() string
}

// PublicKey represents an ECDSA public key.
// It wraps the standard ecdsa.PublicKey and provides additional functionality
// for encoding, verification, and format conversion.
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
	// Input validation
	if k == nil || k.Curve == nil || hash == nil {
		return false
	}
	if len(data) == 0 || len(signature) == 0 {
		return false
	}
	
	keySize := int(math.Ceil(float64(k.Curve.Params().BitSize) / byteBase))
	if len(signature) != 2*keySize {
		return false
	}

	r := big.NewInt(0).SetBytes(signature[:keySize])
	s := big.NewInt(0).SetBytes(signature[keySize:])
	hash.Reset()
	hash.Write(data)
	return ecdsa.Verify((*ecdsa.PublicKey)(k), hash.Sum(nil), r, s)

}

func (k *PublicKey) Bytes() []byte {
	keySize := int(math.Ceil(float64(k.Curve.Params().BitSize) / byteBase))
	x := make([]byte, keySize)
	ox := k.X.Bytes()
	copy(x[keySize-len(ox):], ox)
	y := make([]byte, keySize)
	oy := k.Y.Bytes()
	copy(y[keySize-len(oy):], oy)
	return append(append([]byte{UncompressedPointFormat}, x...), y...)
}

func (k *PublicKey) CompressedBytes() []byte {
	keySize := int(math.Ceil(float64(k.Curve.Params().BitSize) / byteBase))
	x := make([]byte, keySize)
	ox := k.X.Bytes()
	copy(x[keySize-len(ox):], ox)
	if k.Y.Bit(0) == 0 {
		return append([]byte{CompressedEvenYFormat}, x...)
	} else {
		return append([]byte{CompressedOddYFormat}, x...)
	}
}

func (k *PublicKey) Hex() string {
	// Optimize string operations by pre-allocating buffer
	bytes := k.Bytes()
	hexStr := make([]byte, hex.EncodedLen(len(bytes)))
	hex.Encode(hexStr, bytes)
	
	// Convert to uppercase in-place for better performance
	for i := 0; i < len(hexStr); i++ {
		if hexStr[i] >= 'a' && hexStr[i] <= 'f' {
			hexStr[i] -= 32 // Convert to uppercase
		}
	}
	
	return string(hexStr)
}

// Private interface defines methods for ECDSA private key operations.
// It provides functionality for digital signing, key encoding, and format conversion.
type Private interface {
	// PEM returns the private key encoded in PEM format
	PEM() string
	// Key returns the underlying ecdsa.PrivateKey
	Key() *ecdsa.PrivateKey
	// Public returns the corresponding public key
	Public() PublicKey
	// Sign creates a digital signature of data using the specified hash algorithm
	Sign(data []byte, hash hash.Hash) []byte
	// Bytes returns the private key as byte slice
	Bytes() []byte
	// PrivateKeyHex returns the private key as uppercase hexadecimal string
	PrivateKeyHex() string
}

// PrivateKey represents an ECDSA private key.
// It wraps the standard ecdsa.PrivateKey and provides additional functionality
// for signing, encoding, and format conversion.
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
	// Input validation
	if k == nil || k.Curve == nil || hash == nil {
		return nil
	}
	if len(data) == 0 {
		return nil
	}
	
	keySize := int(math.Ceil(float64(k.Curve.Params().BitSize) / byteBase))
	hash.Reset()
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
	// Optimize string operations by pre-allocating buffer
	bytes := k.Bytes()
	hexStr := make([]byte, hex.EncodedLen(len(bytes)))
	hex.Encode(hexStr, bytes)
	
	// Convert to uppercase in-place for better performance
	for i := 0; i < len(hexStr); i++ {
		if hexStr[i] >= 'a' && hexStr[i] <= 'f' {
			hexStr[i] -= 32 // Convert to uppercase
		}
	}
	
	return string(hexStr)
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

func UnmarshalECPublicKey(curve EllipticCurve, bs []byte) *PublicKey {
	// Input validation
	if curve == nil || len(bs) == 0 {
		return nil
	}
	
	var x, y *big.Int
	if bs[0] == UncompressedPointFormat {
		x, y = elliptic.Unmarshal(curve, bs)
	} else if bs[0] == CompressedEvenYFormat || bs[0] == CompressedOddYFormat {
		x, y = elliptic.UnmarshalCompressed(curve, bs)
	} else {
		// Unknown point format
		return nil
	}

	if x == nil || y == nil {
		return nil
	}

	return &PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
}
