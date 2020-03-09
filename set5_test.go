package cpals

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/jbert/cpals-go/cbig"
)

func TestS5C33a(t *testing.T) {

	// Inline diffie-helman with small ints
	p := 37
	g := 5

	a := rand.Intn(p)
	A := intExpMod(g, a, p)
	b := rand.Intn(p)
	B := intExpMod(g, b, p)

	s := intExpMod(B, a, p)
	s2 := intExpMod(A, b, p)
	if s == s2 {
		t.Logf("Session key: %d - yay", s)
	} else {
		t.Fatalf("Failed to get same session key from two rando numbers: %d != %d", s, s2)
	}
}

func TestS5C33c(t *testing.T) {

	toBig := func(n int) *big.Int {
		return big.NewInt(int64(n))
	}

	// Inline diffie-helman with small ints
	p := toBig(37)
	g := toBig(5)

	t.Logf("DH: p %s", p)
	t.Logf("DH: g %s", g)

	a := cbig.BigRand(p)
	A := cbig.BigExpMod(g, a, p)
	t.Logf("DH: a %s", a)
	t.Logf("DH: A %s", A)

	b := cbig.BigRand(p)
	B := cbig.BigExpMod(g, b, p)

	t.Logf("DH: b %s", b)
	t.Logf("DH: B %s", B)

	s := cbig.BigExpMod(B, a, p)
	s2 := cbig.BigExpMod(A, b, p)
	if cbig.BigEqual(s, s2) {
		t.Logf("Session key: %s - yay", s.String())
	} else {
		t.Fatalf("Failed to get same session key from two rando numbers: %s != %s", s.String(), s2.String())
	}
}

func TestS5C33b(t *testing.T) {

	p := cbig.BigFromHex(`
			ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
			e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
			3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
			6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
			24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
			c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
			bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
			fffffffffffff
			`)
	g := big.NewInt(2)
	//	t.Error("Remove me...")
	//	p = big.NewInt(37)
	//	g = big.NewInt(5)

	t.Logf("DH: p %s", p)
	t.Logf("DH: g %s", g)

	a := cbig.BigRand(p)
	A := cbig.BigExpMod(g, a, p)

	t.Logf("DH: a %s", a)
	t.Logf("DH: A %s", A)

	b := cbig.BigRand(p)
	B := cbig.BigExpMod(g, b, p)

	t.Logf("DH: b %s", b)
	t.Logf("DH: B %s", B)

	s := cbig.BigExpMod(A, b, p)
	s2 := cbig.BigExpMod(B, a, p)
	if cbig.BigEqual(s, s2) {
		t.Logf("Session key: %d - yay", s)
	} else {
		t.Fatalf("Failed to get same session key from two rando numbers: %d != %d", s, s2)
	}

	b.Add(b, big.NewInt(-1))
	s3 := cbig.BigExpMod(b, A, p)
	if cbig.BigEqual(s, s3) {
		t.Fatalf("Changing priv key does not change session key :-(")
	}
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

func TestExpMod(t *testing.T) {
	testCases := []struct {
		g, a, p, v int
	}{
		{1, 100, 7, 1},
		{3, 1, 13, 3},
		{3, 2, 13, 9},
		{3, 3, 13, 1},
		{3, 4, 13, 3},
	}

	for _, tc := range testCases {
		t.Log(tc)
		t.Run("INT", func(t *testing.T) {
			gotV := intExpMod(tc.g, tc.a, tc.p)
			if gotV != tc.v {
				t.Fatalf("Failed: got %d expected %d", gotV, tc.v)
			}
		})

		toBig := func(v int) *big.Int {
			return big.NewInt(int64(v))
		}
		t.Run("BIG", func(t *testing.T) {
			g := toBig(tc.g)
			a := toBig(tc.a)
			p := toBig(tc.p)
			expectedV := toBig(tc.v)
			gotV := cbig.BigExpMod(g, a, p)
			if !cbig.BigEqual(gotV, expectedV) {
				t.Fatalf("Failed: got %s expected %s", gotV, expectedV)
			}
		})
	}
}
