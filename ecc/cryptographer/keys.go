package cryptographer

import (
	"math/big"
)

type PublicKey struct {
	Point Point
}

type PrivateKey struct {
	Key big.Int
}

type KeyPair struct {
	PublicKey  PublicKey
	PrivateKey PrivateKey
}

type Signature struct {
	R big.Int
	S big.Int
}
