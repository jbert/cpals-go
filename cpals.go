package cpals // import "github.com/jbert/cpals-go

import (
	"encoding/base64"
	"encoding/hex"
)

func DeHex(in string) ([]byte, error) {
	return hex.DecodeString(in)
}

func Base64(in []byte) string {
	return base64.StdEncoding.EncodeToString(in)
}
