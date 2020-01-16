package cpals // import "github.com/jbert/cpals-go

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

type HexStr string
type B64Str string

func DeHex(in HexStr) ([]byte, error) {
	return hex.DecodeString(string(in))
}

func Base64(in []byte) B64Str {
	return B64Str(base64.StdEncoding.EncodeToString(in))
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
