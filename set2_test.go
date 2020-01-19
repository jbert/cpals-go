package cpals

import (
	"fmt"
	"math/rand"
	"testing"
)

func TestS2C11(t *testing.T) {
	numTries := 50

	repeatedPlainText := make([]byte, AESBlockSize*10)

	for i := 0; i < numTries; i++ {
		buf, wasECB := EncryptionOracle(repeatedPlainText)
		got := IsECB(buf)
		if got != wasECB {
			t.Errorf("Failed to guess on try %d", i)
		}
	}
	t.Logf("Ran %d tries", numTries)
}

func IsECB(buf []byte) bool {
	dup := BytesFindDuplicateBlock(buf, AESBlockSize)
	return dup != nil
}

func EncryptionOracle(msg []byte) ([]byte, bool) {
	msg = append(RandomRandomBytes(5, 10), msg...)
	msg = append(msg, RandomRandomBytes(5, 10)...)
	n := rand.Int()
	key := RandomKey()
	if n%2 == 0 {
		iv := RandomKey()
		return AESCBCEncrypt(key, iv, msg), false
	} else {
		return AESECBEncrypt(key, msg), true
	}
}

func TestS2C10(t *testing.T) {
	buf := MustLoadB64("10.txt")
	msg := AESCBCDecrypt(YellowKey, ZeroIV, buf)
	t.Log(string(msg))
}

func TestS2C9(t *testing.T) {
	yellowSub := []byte("YELLOW SUBMARINE")

	testCases := []struct {
		in        []byte
		expected  []byte
		blockSize int
	}{
		{
			[]byte{0, 0, 0, 0, 0, 0, 0, 0},
			[]byte{0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 8, 8, 8, 8, 8, 8},
			8,
		},
		{
			[]byte{0, 0, 0, 0, 0, 0, 0},
			[]byte{0, 0, 0, 0, 0, 0, 0, 1},
			8,
		},
		{
			[]byte{0, 0, 0, 0, 0, 0},
			[]byte{0, 0, 0, 0, 0, 0, 2, 2},
			8,
		},
		{
			[]byte{0, 0, 0},
			[]byte{0, 0, 0, 5, 5, 5, 5, 5},
			8,
		},
		{
			[]byte{},
			[]byte{8, 8, 8, 8, 8, 8, 8, 8},
			8,
		},
		{
			[]byte{0},
			[]byte{0, 7, 7, 7, 7, 7, 7, 7},
			8,
		},
		{
			yellowSub,
			append(yellowSub, []byte{4, 4, 4, 4}...),
			20,
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%v", tc.in), func(t *testing.T) {
			got := BytesPKCS7Pad(tc.in, tc.blockSize)
			if !BytesEqual(got, tc.expected) {
				t.Fatalf("got %v expected %v", got, tc.expected)
			}
		})
	}
}
