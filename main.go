package main

import (
	"fmt"
	"go-ecc/ecc/cryptographer"
)

func main() {
	fmt.Println("hello world")

	i := cryptographer.Cryptographer{
		Curve: cryptographer.SECP256k1(),
	}

	i.Encrypt()
}
