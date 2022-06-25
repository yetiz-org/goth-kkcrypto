package kkcrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewES256(t *testing.T) {
	for i := 0; i < 10; i++ {
		es := NewES256()
		data := make([]byte, 1025)
		rand.Read(data)
		assert.True(t, es.PublicKey().Verify(data, es.PrivateKey().Sign(data, es.Hash()), es.Hash()))
		assert.True(t, es.Verify(data, es.Sign(data)))
		assert.Equal(t, es.D().String(), (&big.Int{}).SetBytes(es.PrivateKey().Bytes()).String())
		assert.Equal(t, 32, len(es.PrivateKey().Bytes()))
		assert.Equal(t, 65, len(es.PublicKey().Bytes()))
		assert.Equal(t, 33, len(es.PublicKey().CompressedBytes()))
		assert.Equal(t, es.PublicKey().Bytes()[1:33], es.PublicKey().CompressedBytes()[1:])
		assert.NotEmpty(t, es.PrivateKey().PEM())
		assert.NotEmpty(t, es.PublicKey().PEM())
		assert.Equal(t, es.PublicKey().Y.Bytes(), UnmarshalECPublicKey(es.Curve(), es.PublicKey().Bytes()).Y.Bytes())
		assert.Equal(t, es.PublicKey().Y.Bytes(), UnmarshalECPublicKey(es.Curve(), es.PublicKey().CompressedBytes()).Y.Bytes())
	}
}

func TestNewES384(t *testing.T) {
	for i := 0; i < 10; i++ {
		es := NewES384()
		data := make([]byte, 1025)
		rand.Read(data)
		assert.True(t, es.PublicKey().Verify(data, es.PrivateKey().Sign(data, es.Hash()), es.Hash()))
		assert.True(t, es.Verify(data, es.Sign(data)))
		assert.Equal(t, es.D().String(), (&big.Int{}).SetBytes(es.PrivateKey().Bytes()).String())
		assert.Equal(t, 48, len(es.PrivateKey().Bytes()))
		assert.Equal(t, 97, len(es.PublicKey().Bytes()))
		assert.Equal(t, 49, len(es.PublicKey().CompressedBytes()))
		assert.Equal(t, es.PublicKey().Bytes()[1:49], es.PublicKey().CompressedBytes()[1:])
		assert.NotEmpty(t, es.PrivateKey().PEM())
		assert.NotEmpty(t, es.PublicKey().PEM())
		assert.Equal(t, es.PublicKey().Y.Bytes(), UnmarshalECPublicKey(es.Curve(), es.PublicKey().Bytes()).Y.Bytes())
		assert.Equal(t, es.PublicKey().Y.Bytes(), UnmarshalECPublicKey(es.Curve(), es.PublicKey().CompressedBytes()).Y.Bytes())
	}
}

func TestNewES512(t *testing.T) {
	for i := 0; i < 10; i++ {
		es := NewES512()
		data := make([]byte, 1025)
		eso := &ES{
			Private: (*PrivateKey)(&ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{
					Curve: es.Curve(),
					X:     es.X(),
					Y:     es.Y(),
				},
				D: es.D(),
			}),
			HashId: crypto.SHA512,
		}

		rand.Read(data)
		assert.True(t, eso.PublicKey().Verify(data, es.PrivateKey().Sign(data, es.Hash()), es.Hash()))
		assert.True(t, eso.Verify(data, es.Sign(data)))
		assert.Equal(t, eso.D().String(), (&big.Int{}).SetBytes(es.PrivateKey().Bytes()).String())
		assert.Equal(t, 66, len(es.PrivateKey().Bytes()))
		assert.Equal(t, 133, len(es.PublicKey().Bytes()))
		assert.Equal(t, 67, len(es.PublicKey().CompressedBytes()))
		assert.Equal(t, es.PublicKey().Bytes()[1:67], es.PublicKey().CompressedBytes()[1:])
		assert.NotEmpty(t, es.PrivateKey().PEM())
		assert.NotEmpty(t, es.PublicKey().PEM())
		assert.Equal(t, es.PublicKey().Y.Bytes(), UnmarshalECPublicKey(es.Curve(), es.PublicKey().Bytes()).Y.Bytes())
		assert.Equal(t, es.PublicKey().Y.Bytes(), UnmarshalECPublicKey(es.Curve(), es.PublicKey().CompressedBytes()).Y.Bytes())
	}
}
