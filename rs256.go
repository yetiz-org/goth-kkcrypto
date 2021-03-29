package kkcrypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

type RS256 struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

func (r *RS256) PEMPrivateKey() string {
	x509Encoded, _ := x509.MarshalPKCS8PrivateKey(r.PrivateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509Encoded,
	})

	return string(pemEncoded)
}

func (r *RS256) PEMPassphrasePrivateKey(passphrase string) string {
	x509Encoded, _ := x509.MarshalPKCS8PrivateKey(r.PrivateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509Encoded,
	}

	block, _ = x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(passphrase), x509.PEMCipherAES256)
	pemEncoded := pem.EncodeToMemory(block)
	return string(pemEncoded)
}

func (r *RS256) PEMPublicKey() string {
	x509Encoded, _ := x509.MarshalPKIXPublicKey(r.PublicKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509Encoded,
	})

	return string(pemEncoded)
}

func NewRS256() *RS256 {
	rs256 := RS256{}
	privateKey, _ := rsa.GenerateKey(rand.Reader, 4096)
	rs256.PrivateKey = privateKey
	rs256.PublicKey = &privateKey.PublicKey
	return &rs256
}
