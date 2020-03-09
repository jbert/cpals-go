package cbig

import (
	"fmt"
	"math/big"
	"math/rand"
	"strings"
)

var source = rand.NewSource(0)
var rnd = rand.New(source)

func BigStr(n *big.Int) string {
	s := n.String()
	upTo := 16
	if len(s) < upTo {
		upTo = len(s)
	}
	return fmt.Sprintf("%d:%s", len(s), s[0:upTo])
}

func BigFromHex(s string) *big.Int {
	var n big.Int
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\t", "")
	_, ok := n.SetString(s, 16)
	if !ok {
		panic(fmt.Sprintf("Failed to set int from string: %s", s))
	}
	return &n
}

func BigRand(upTo *big.Int) *big.Int {
	var n big.Int
	n.Rand(rnd, upTo)
	return &n
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

func intExpMod(g, a, p int) int {
	v := 1
	e := g
	for a > 0 {

		if a%2 == 1 {
			v *= e
			v %= p
		}

		a >>= 1
		e *= e
		e %= p
	}
	if v < 0 {
		v += p
	}
	return v
}

*/
func BigExpMod(g, aArg, p *big.Int) *big.Int {
	a := BigCopy(aArg)
	v := big.NewInt(1)
	e := BigCopy(g)

	zero := big.NewInt(0)
	one := big.NewInt(1)
	two := big.NewInt(2)

	for a.Cmp(zero) > 0 {

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
