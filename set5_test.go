package cpals

import (
	"math/rand"
	"testing"
)

func TestS5C33(t *testing.T) {

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
		gotV := intExpMod(tc.g, tc.a, tc.p)
		if gotV != tc.v {
			t.Fatalf("Failed: got %d expected %d", gotV, tc.v)
		}
	}
}
