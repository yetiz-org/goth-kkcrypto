package kkcrypto

import (
	"crypto/elliptic"
)

type EllipticCurve elliptic.Curve

func P256() EllipticCurve {
	return elliptic.P256()
}

func Secp256r1() EllipticCurve {
	return P256()
}

func Prime256v1() EllipticCurve {
	return P256()
}

func P384() EllipticCurve {
	return elliptic.P384()
}

func Secp384r1() EllipticCurve {
	return P384()
}

func P521() EllipticCurve {
	return elliptic.P521()
}

func Secp521r1() EllipticCurve {
	return P521()
}
