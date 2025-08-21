package kkcrypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

// RS256 represents an RSA key pair for RSASSA-PKCS1-v1_5 signature algorithm using SHA-256.
// It provides methods for key generation, PEM encoding, and cryptographic operations.
type RS256 struct {
	// PrivateKey holds the RSA private key for signing operations
	PrivateKey *rsa.PrivateKey
	// PublicKey holds the RSA public key for verification operations
	PublicKey  *rsa.PublicKey
}

// PEMPrivateKey returns the RSA private key encoded in PEM format.
// Returns an empty string if encoding fails.
func (r *RS256) PEMPrivateKey() string {
	if r == nil || r.PrivateKey == nil {
		return ""
	}
	x509Encoded, err := x509.MarshalPKCS8PrivateKey(r.PrivateKey)
	if err != nil {
		return ""
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509Encoded,
	})

	return string(pemEncoded)
}

// PEMPassphrasePrivateKey returns the RSA private key encoded in PEM format with passphrase protection.
// The private key is encrypted using AES-256 cipher with the provided passphrase.
// Returns an empty string if encoding or encryption fails.
func (r *RS256) PEMPassphrasePrivateKey(passphrase string) string {
	if r == nil || r.PrivateKey == nil {
		return ""
	}
	x509Encoded, err := x509.MarshalPKCS8PrivateKey(r.PrivateKey)
	if err != nil {
		return ""
	}
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509Encoded,
	}

	encryptedBlock, err := x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(passphrase), x509.PEMCipherAES256)
	if err != nil {
		return ""
	}
	pemEncoded := pem.EncodeToMemory(encryptedBlock)
	return string(pemEncoded)
}

// PEMPublicKey returns the RSA public key encoded in PEM format.
// Returns an empty string if encoding fails.
func (r *RS256) PEMPublicKey() string {
	if r == nil || r.PublicKey == nil {
		return ""
	}
	x509Encoded, err := x509.MarshalPKIXPublicKey(r.PublicKey)
	if err != nil {
		return ""
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509Encoded,
	})

	return string(pemEncoded)
}

// NewRS256 creates a new RS256 instance with a freshly generated 4096-bit RSA key pair.
// Returns nil if key generation fails.
// The generated key uses cryptographically secure random number generation.
func NewRS256() *RS256 {
	rs256 := RS256{}
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil
	}
	rs256.PrivateKey = privateKey
	rs256.PublicKey = &privateKey.PublicKey
	return &rs256
}
