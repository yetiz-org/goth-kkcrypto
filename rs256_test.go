package kkcrypto

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewRS256(t *testing.T) {
	for i := 0; i < 5; i++ {
		rs256 := NewRS256()
		assert.NotNil(t, rs256, "NewRS256 should not return nil")
		assert.NotNil(t, rs256.PrivateKey, "PrivateKey should not be nil")
		assert.NotNil(t, rs256.PublicKey, "PublicKey should not be nil")
		
		// Verify key size is 4096 bits
		assert.Equal(t, 4096, rs256.PrivateKey.Size()*8, "Private key should be 4096 bits")
		assert.Equal(t, 4096, rs256.PublicKey.Size()*8, "Public key should be 4096 bits")
		
		// Verify public key matches private key
		assert.Equal(t, &rs256.PrivateKey.PublicKey, rs256.PublicKey, "Public key should match private key's public key")
	}
}

func TestRS256_PEMPrivateKey(t *testing.T) {
	rs256 := NewRS256()
	assert.NotNil(t, rs256, "NewRS256 should not return nil")
	
	pemPrivate := rs256.PEMPrivateKey()
	assert.NotEmpty(t, pemPrivate, "PEM private key should not be empty")
	assert.Contains(t, pemPrivate, "-----BEGIN RSA PRIVATE KEY-----", "PEM should contain RSA private key header")
	assert.Contains(t, pemPrivate, "-----END RSA PRIVATE KEY-----", "PEM should contain RSA private key footer")
	
	// Test with nil private key (edge case)
	rs256Nil := &RS256{}
	pemNil := rs256Nil.PEMPrivateKey()
	assert.Empty(t, pemNil, "PEM private key should be empty for nil private key")
}

func TestRS256_PEMPassphrasePrivateKey(t *testing.T) {
	rs256 := NewRS256()
	assert.NotNil(t, rs256, "NewRS256 should not return nil")
	
	passphrase := "test-passphrase-12345"
	pemEncrypted := rs256.PEMPassphrasePrivateKey(passphrase)
	assert.NotEmpty(t, pemEncrypted, "Encrypted PEM private key should not be empty")
	assert.Contains(t, pemEncrypted, "-----BEGIN RSA PRIVATE KEY-----", "Encrypted PEM should contain RSA private key header")
	assert.Contains(t, pemEncrypted, "-----END RSA PRIVATE KEY-----", "Encrypted PEM should contain RSA private key footer")
	
	// Verify it's different from unencrypted version
	pemPlain := rs256.PEMPrivateKey()
	assert.NotEqual(t, pemPlain, pemEncrypted, "Encrypted PEM should be different from plain PEM")
	
	// Test with empty passphrase
	pemEmptyPass := rs256.PEMPassphrasePrivateKey("")
	assert.NotEmpty(t, pemEmptyPass, "PEM with empty passphrase should still work")
	
	// Test with nil private key (edge case)
	rs256Nil := &RS256{}
	pemNil := rs256Nil.PEMPassphrasePrivateKey(passphrase)
	assert.Empty(t, pemNil, "Encrypted PEM should be empty for nil private key")
}

func TestRS256_PEMPublicKey(t *testing.T) {
	rs256 := NewRS256()
	assert.NotNil(t, rs256, "NewRS256 should not return nil")
	
	pemPublic := rs256.PEMPublicKey()
	assert.NotEmpty(t, pemPublic, "PEM public key should not be empty")
	assert.Contains(t, pemPublic, "-----BEGIN RSA PUBLIC KEY-----", "PEM should contain RSA public key header")
	assert.Contains(t, pemPublic, "-----END RSA PUBLIC KEY-----", "PEM should contain RSA public key footer")
	
	// Test with nil public key (edge case)
	rs256Nil := &RS256{}
	pemNil := rs256Nil.PEMPublicKey()
	assert.Empty(t, pemNil, "PEM public key should be empty for nil public key")
}

func TestRS256_KeyConsistency(t *testing.T) {
	// Test that multiple calls to NewRS256 generate different keys
	rs256_1 := NewRS256()
	rs256_2 := NewRS256()
	
	assert.NotNil(t, rs256_1, "First RS256 should not be nil")
	assert.NotNil(t, rs256_2, "Second RS256 should not be nil")
	
	// Keys should be different
	assert.NotEqual(t, rs256_1.PrivateKey, rs256_2.PrivateKey, "Private keys should be different")
	assert.NotEqual(t, rs256_1.PublicKey, rs256_2.PublicKey, "Public keys should be different")
	
	// PEM encodings should be different
	assert.NotEqual(t, rs256_1.PEMPrivateKey(), rs256_2.PEMPrivateKey(), "PEM private keys should be different")
	assert.NotEqual(t, rs256_1.PEMPublicKey(), rs256_2.PEMPublicKey(), "PEM public keys should be different")
}

func TestRS256_PEMFormats(t *testing.T) {
	rs256 := NewRS256()
	assert.NotNil(t, rs256, "NewRS256 should not return nil")
	
	// Test that PEM formats are valid and consistent
	pemPrivate := rs256.PEMPrivateKey()
	pemPublic := rs256.PEMPublicKey()
	pemEncrypted := rs256.PEMPassphrasePrivateKey("test123")
	
	// All should be non-empty
	assert.NotEmpty(t, pemPrivate, "Private PEM should not be empty")
	assert.NotEmpty(t, pemPublic, "Public PEM should not be empty")
	assert.NotEmpty(t, pemEncrypted, "Encrypted PEM should not be empty")
	
	// Check line endings and formatting
	assert.Contains(t, pemPrivate, "\n", "Private PEM should contain newlines")
	assert.Contains(t, pemPublic, "\n", "Public PEM should contain newlines")
	assert.Contains(t, pemEncrypted, "\n", "Encrypted PEM should contain newlines")
	
	// Verify proper PEM structure
	lines := []string{pemPrivate, pemPublic, pemEncrypted}
	for i, pem := range lines {
		assert.True(t, len(pem) > 100, "PEM %d should have substantial content", i)
		// PEM should end with newline
		assert.Equal(t, "\n", pem[len(pem)-1:], "PEM %d should end with newline", i)
	}
}

func TestRS256_ErrorConditions(t *testing.T) {
	// Test behavior with corrupted or nil components
	rs256 := &RS256{}
	
	// All methods should handle nil gracefully
	assert.Empty(t, rs256.PEMPrivateKey(), "PEMPrivateKey should return empty string for nil key")
	assert.Empty(t, rs256.PEMPublicKey(), "PEMPublicKey should return empty string for nil key")
	assert.Empty(t, rs256.PEMPassphrasePrivateKey("test"), "PEMPassphrasePrivateKey should return empty string for nil key")
}

func TestRS256_LargePassphrase(t *testing.T) {
	rs256 := NewRS256()
	assert.NotNil(t, rs256, "NewRS256 should not return nil")
	
	// Test with very long passphrase
	longPassphrase := make([]byte, 1000)
	rand.Read(longPassphrase)
	
	pemLong := rs256.PEMPassphrasePrivateKey(string(longPassphrase))
	assert.NotEmpty(t, pemLong, "PEM with long passphrase should work")
	assert.Contains(t, pemLong, "-----BEGIN RSA PRIVATE KEY-----", "PEM should contain RSA private key header")
}
