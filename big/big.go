package big

import (
	"fmt"
	"math/big"
	"math/rand"
	"strings"
)

var source = rand.NewSource(0)
var rnd = rand.New(source)

func BigFromHex(s string) *big.Int {
	var n big.Int
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, " ", "")
	_, ok := n.SetString(s, 16)
	if !ok {
		panic(fmt.Sprintf("Failed to set int from string: %s", s))
	}
	return &n
}

func BigRand(upTo *big.Int) *big.Int {
	return big.NewInt(0).Rand(rnd, upTo)
}

func BigCopy(a *big.Int) *big.Int {
	var b big.Int
	b.Set(a)
	return &b
}

/*
func BigExpMod(g, a, p *big.Int) *big.Int {
	var n big.Int
	n.Exp(g, a, p)
	return &n
}
*/
func BigExpMod(g, a, p *big.Int) *big.Int {
	v := big.NewInt(1)
	e := BigCopy(g)

	zero := big.NewInt(0)
	one := big.NewInt(1)
	two := big.NewInt(2)

	for a.Cmp(zero) < 0 {

		amod2 := big.NewInt(0)
		amod2.Mod(a, two)

		if BigEqual(amod2, one) {
			v.Mul(v, e)
			v.Mod(v, p)
		}

		a.Div(a, two)
		e.Mul(e, e)
		e.Mod(e, p)
	}
	if v.Cmp(zero) < 0 {
		v.Add(v, p)
	}
	return v
}

func BigEqual(a, b *big.Int) bool {
	return a.Cmp(b) == 0
}
