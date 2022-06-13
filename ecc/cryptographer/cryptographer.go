package cryptographer

import (
	"crypto/rand"
	"crypto/sha256"
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

func (c Cryptographer) generateSecureSignatureK() big.Int {
	return generateSecureRandom(c.Scheme.order)
}

func (c Cryptographer) Sign(key PrivateKey, s string) Signature {

	k := c.generateSecureSignatureK()
	R := c.pointMultiplication(c.Scheme.basePoint, k)
	r := R.x.Mod(&R.x, &c.Scheme.prime)

	rda := new(big.Int).Mul(r, &key.Key)
	zrda := new(big.Int).Add(rda, big.NewInt(0).SetBytes(c.hashMessage(s)))
	kzrda := zrda.Mul(zrda, c.inverse(k))

	sig := kzrda.Mod(kzrda, &c.Scheme.prime)

	return Signature{
		R: *r,
		S: *sig,
	}
}

func (c Cryptographer) Verify(pk PublicKey, signature Signature, s string) int {
	digest := c.hashMessage(s)

	u1 := big.NewInt(0).SetBytes(digest)
	u2 := big.NewInt(0).Mul(u1, c.inverse(signature.S))

	v1 := big.NewInt(0).Mul(&signature.R, c.inverse(signature.S))

	point := c.pointAddition(c.pointMultiplication(c.Scheme.basePoint, *u2), c.pointMultiplication(pk.Point, *v1))
	return signature.R.Cmp(point.x.Mod(&point.x, &c.Scheme.prime))
}

func (c Cryptographer) hashMessage(s string) []byte {
	// Might not work with other than SECP256k1, as need same length as prime.
	// Should truncate for general solution.
	hasher := sha256.New()
	hasher.Write([]byte(s))
	return hasher.Sum(nil)
}

func (c Cryptographer) inverse(k big.Int) *big.Int {
	two := big.NewInt(2)
	nMinus2 := new(big.Int).Sub(&c.Scheme.prime, two)
	return new(big.Int).Exp(&k, nMinus2, &c.Scheme.prime)
}

func generateSecureRandom(max big.Int) big.Int {
	n, err := rand.Int(rand.Reader, &max)
	if err != nil {
		print("Generating secure random failed.")
	}
	return *n
}

func (c Cryptographer) pointAddition(p Point, q Point) Point {

	if p.x.Cmp(big.NewInt(0)) == 0 && p.y.Cmp(big.NewInt(0)) == 0 {
		return Point{q.x, q.y}
	}
	if q.x.Cmp(big.NewInt(0)) == 0 && q.y.Cmp(big.NewInt(0)) == 0 {
		return Point{p.x, p.y}
	}

	var l = big.NewInt(0)
	var v1, v2 = big.NewInt(2), big.NewInt(3)

	if p.equals(q) {
		var s1 = big.NewInt(0).Exp(&p.x, v1, nil)
		var s2 = big.NewInt(0).Mul(s1, v2)
		var s3 = big.NewInt(0).Add(s2, &c.Scheme.curve.a)

		var g1 = big.NewInt(0).Mul(&p.y, v2)

		var s4 = big.NewInt(0).Mul(s3, g1)
		l = s4.ModInverse(s4, &c.Scheme.prime)
	} else {
		var s1 = big.NewInt(0).Sub(&q.y, &p.y)
		var s2 = big.NewInt(0).Sub(&q.x, &p.x)
		var s3 = big.NewInt(0).Mul(s1, s2)
		l = big.NewInt(0).ModInverse(s3, &c.Scheme.prime)
	}

	var x1 = big.NewInt(0).Exp(l, v1, nil)
	var x2 = big.NewInt(0).Sub(x1, &p.x)
	var x3 = big.NewInt(0).Sub(x2, &q.x)

	var y1 = big.NewInt(0).Sub(&p.x, x3)
	var y2 = big.NewInt(0).Mul(l, y1)
	var y3 = big.NewInt(0).Mod(y2, &c.Scheme.prime)

	return Point{*x3, *y3}
}

func (c Cryptographer) pointMultiplication(g Point, d big.Int) Point {
	var n = g
	var q = Point{*big.NewInt(-1), *big.NewInt(-1)}
	for i := 0; i <= d.BitLen(); i++ {
		if d.Bit(i) == 1 {
			q = c.pointAddition(q, n)
		}
		n = c.pointAddition(n, n)
	}
	return q
}
