package main

import (
	"fmt"
	"go-ecc/ecc/cryptographer"
)

func main() {

	i := cryptographer.Cryptographer{
		Scheme: cryptographer.SECP256k1(),
	}

	num := i.GeneratePrivateKey().Key
	addr := &num

	fmt.Print(addr.String())
	pair := i.GenerateKeyPair()
	fmt.Println(pair)
}
