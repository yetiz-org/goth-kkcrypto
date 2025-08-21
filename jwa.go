package kkcrypto

// JSON Web Algorithm (JWA) constants for cryptographic algorithms
// These constants are used to identify specific algorithms in JWT and JWS specifications
var (
	// AlgES256 represents the ECDSA using P-256 curve and SHA-256 hash algorithm
	AlgES256 = "ES256"
	
	// AlgHS256 represents the HMAC using SHA-256 hash algorithm
	AlgHS256 = "HS256"
	
	// AlgRS256 represents the RSASSA-PKCS1-v1_5 using SHA-256 hash algorithm
	AlgRS256 = "RS256"
)
