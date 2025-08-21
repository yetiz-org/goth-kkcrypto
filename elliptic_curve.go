// Package kkcrypto provides cryptographic utilities for elliptic curve and RSA operations.
package kkcrypto

import (
	"crypto/elliptic"
)

// EllipticCurve is an alias for the standard elliptic.Curve interface.
// It provides access to elliptic curve parameters and operations.
type EllipticCurve elliptic.Curve

// P256 returns the NIST P-256 (secp256r1) elliptic curve.
// This is a widely used 256-bit prime curve standardized by NIST.
func P256() EllipticCurve {
	return elliptic.P256()
}

// Secp256r1 returns the secp256r1 elliptic curve.
// This is an alias for P256() providing the same 256-bit prime curve.
func Secp256r1() EllipticCurve {
	return P256()
}

// Prime256v1 returns the prime256v1 elliptic curve.
// This is an alias for P256() providing the same 256-bit prime curve.
func Prime256v1() EllipticCurve {
	return P256()
}

// P384 returns the NIST P-384 (secp384r1) elliptic curve.
// This is a 384-bit prime curve standardized by NIST.
func P384() EllipticCurve {
	return elliptic.P384()
}

// Secp384r1 returns the secp384r1 elliptic curve.
// This is an alias for P384() providing the same 384-bit prime curve.
func Secp384r1() EllipticCurve {
	return P384()
}

// P521 returns the NIST P-521 (secp521r1) elliptic curve.
// This is a 521-bit prime curve standardized by NIST.
func P521() EllipticCurve {
	return elliptic.P521()
}

// Secp521r1 returns the secp521r1 elliptic curve.
// This is an alias for P521() providing the same 521-bit prime curve.
func Secp521r1() EllipticCurve {
	return P521()
}
