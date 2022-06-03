package cryptographer

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

type Cryptographer struct {
	Scheme Scheme
}

func (c Cryptographer) Encrypt() {

	fmt.Printf("%s oeu r \n", c.Scheme.curve.a)
}

func (c Cryptographer) GenerateKeyPair() KeyPair {
	private := c.GeneratePrivateKey()
	public := c.pointMultiplication(c.Scheme.basePoint, private.Key)
	return KeyPair{
		PublicKey:  PublicKey{public},
		PrivateKey: private,
	}
}

func (c Cryptographer) GeneratePrivateKey() PrivateKey {
	private := PrivateKey{
		Key: generateSecureRandom(c.Scheme.order),
	}
	return private
}

func generateSecureRandom(max big.Int) big.Int {
	//Generate cryptographically strong pseudo-random between 0 - max
	n, err := rand.Int(rand.Reader, &max)
	if err != nil {
		print("Generating secure random failed.")
	}
	return *n
}

func (c Cryptographer) pointAddition(p Point, q Point) Point {

	var l = big.NewInt(0)
	var v1, v2 = big.NewInt(2), big.NewInt(3)

	if p.equals(q) {
		var s1 = p.x.Exp(&p.x, v1, nil)
		var s2 = s1.Mul(s1, v2)
		var s3 = s2.Add(s2, v2)

		var g1 = p.y.Mul(&p.y, v2)

		var s4 = s3.Mul(s3, g1)
		l = s4.ModInverse(s4, &c.Scheme.prime)
	} else {
		var s1 = q.y.Sub(&q.y, &p.y)
		var s2 = q.x.Sub(&q.x, &p.x)
		var s3 = s1.Mul(s1, s2)
		l = s3.ModInverse(s3, &c.Scheme.prime)
	}

	var x1 = l.Exp(l, v1, nil)
	var x2 = x1.Sub(x1, &p.x)
	var x3 = x2.Sub(x2, &q.x)

	var y1 = p.x.Sub(&p.x, x3)
	var y2 = l.Mul(l, y1)
	var y3 = y2.Mod(y2, &c.Scheme.prime)

	return Point{*x3, *y3}
}

func (c Cryptographer) pointMultiplication(g Point, d big.Int) Point {
	var n = g
	var q = Point{g.x, g.y}
	for i := 0; i <= d.BitLen(); i++ {
		if d.Bit(i) == 1 {
			q = c.pointAddition(q, n)
		}
		n = c.pointAddition(n, n)
	}
	return q
}
