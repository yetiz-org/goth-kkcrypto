package kkcrypto

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewES256(t *testing.T) {
	for i := 0; i < 10; i++ {
		es := NewES256()
		data := make([]byte, 1025)
		rand.Read(data)
		assert.True(t, es.Verify(data, es.Sign(data)))
	}
}

func TestNewES384(t *testing.T) {
	for i := 0; i < 10; i++ {
		es := NewES384()
		data := make([]byte, 1025)
		rand.Read(data)
		assert.True(t, es.Verify(data, es.Sign(data)))
	}
}

func TestNewES512(t *testing.T) {
	for i := 0; i < 10; i++ {
		es := NewES512()
		data := make([]byte, 1025)
		rand.Read(data)
		assert.True(t, es.Verify(data, es.Sign(data)))
	}
}
