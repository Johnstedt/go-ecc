package cryptographer

import "fmt"

type Cryptographer struct {
	Curve Curve
}

func (e Cryptographer) Encrypt() {

	fmt.Printf("%s oeu r \n", e.Curve.a)
}
