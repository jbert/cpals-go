package cpals // import "github.com/jbert/cpals-go

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

type HexStr string
type B64Str string

func (h HexStr) Normalise() HexStr {
	allowed := []byte("01234567890abcdefABCDEF")
	m := make(map[byte]struct{})
	for _, b := range allowed {
		m[b] = struct{}{}
	}
	var g []byte
	for _, c := range []byte(h) {
		if _, ok := m[c]; ok {
			g = append(g, c)
		}
	}
	return HexStr(g)
}

func (h HexStr) Equals(g HexStr) bool {
	return h.Normalise() == g.Normalise()
}

func DeHex(in HexStr) ([]byte, error) {
	return hex.DecodeString(string(in))
}

func EnHex(in []byte) HexStr {
	return HexStr(hex.EncodeToString(in))
}

func Base64(in []byte) B64Str {
	return B64Str(base64.StdEncoding.EncodeToString(in))
}

func XorKey(msg, key []byte) []byte {
	lenKey := len(key)
	lenMsg := len(msg)
	buf := make([]byte, lenMsg)
	for i := range msg {
		j := i % lenKey
		buf[i] = msg[i] ^ key[j]
	}
	return buf
}

func Xor(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("Can't xor len %d != %d", len(a), len(b))
	}
	ret := make([]byte, len(a))
	for i := range a {
		ret[i] = a[i] ^ b[i]
	}
	return ret, nil
}

func BytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func SolveEnglishSingleByteXor(ctxt []byte) ([]byte, float64) {
	var bestB byte
	bestScore := 0.0
	for bi := 0; bi <= 0xff; bi++ {
		b := byte(bi)
		buf := XorByte(ctxt, b)
		score := EnglishScore(buf)
		//fmt.Printf("%02X: %f: %s\n", bi, score, buf)
		if score > bestScore {
			bestB = b
			bestScore = score
		}
	}
	return XorByte(ctxt, bestB), bestScore
}

func XorByte(buf []byte, b byte) []byte {
	ret := make([]byte, len(buf))
	for i := range buf {
		ret[i] = buf[i] ^ b
	}
	return ret
}

func EnglishScore(msg []byte) float64 {
	chars := []byte(" etaoinshrdlu")
	m := make(map[byte]float64)
	for i, b := range chars {
		m[b] = 1 / float64(i+1)
	}

	score := 0.0
	for _, c := range msg {
		if c >= 'A' && c <= 'Z' {
			c = ByteLowerCase(c)
		}
		byteScore, ok := m[c]
		//		fmt.Printf("%c: %f\n", c, byteScore)
		if ok {
			score += byteScore
		}
	}
	return score
}

func ByteLowerCase(b byte) byte {
	return b | 0x20
}
