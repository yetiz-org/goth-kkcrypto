package kkcrypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
)

type ES256 struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
}

func (e *ES256) PEMPrivateKey() string {
	x509Encoded, _ := x509.MarshalECPrivateKey(e.PrivateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: x509Encoded,
	})

	return string(pemEncoded)
}

func (e *ES256) PEMPublicKey() string {
	x509Encoded, _ := x509.MarshalPKIXPublicKey(e.PublicKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PUBLIC KEY",
		Bytes: x509Encoded,
	})

	return string(pemEncoded)
}

func NewES256() *ES256 {
	es256 := ES256{}
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	es256.PrivateKey = privateKey
	es256.PublicKey = &privateKey.PublicKey
	return &es256
}