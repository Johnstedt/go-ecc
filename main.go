package main

import (
	"go-ecc/ecc/cryptographer"
)

func main() {

	i := cryptographer.Cryptographer{
		Scheme: cryptographer.SECP256k1(),
	}

	pair := i.GenerateKeyPair()
	sig := i.Sign(pair.PrivateKey, "the message")
	i.Verify(pair.PublicKey, sig, "the message")
}
