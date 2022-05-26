package cryptographer

import "math/big"

type Key struct {
	Key big.Int
}

type PublicKey struct {
	Key Key
}

type PrivateKey struct {
	Key Key
}

type KeyPair struct {
	PublicKey  PublicKey
	PrivateKey PrivateKey
}
