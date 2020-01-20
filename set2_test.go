package cpals

import (
	"fmt"
	"math/rand"
	"testing"
)

func TestS2C12(t *testing.T) {
	blockSize := FindBlockSize(C12EncryptionOracle)
	t.Logf("Enc oracle has block size: %d", blockSize)
	isECB := IsECB(C12EncryptionOracle, blockSize)
	t.Logf("Enc oracle is ECB: %v", isECB)

	makeDict := func(targetBlock []byte) map[string]byte {
		blockDict := make(map[string]byte)
		workBlock := make([]byte, len(targetBlock)+1)
		copy(workBlock, targetBlock)
		for b := 0; b <= 0xff; b++ {
			workBlock[len(workBlock)-1] = byte(b)
			buf := C12EncryptionOracle(workBlock)
			blockDict[string(buf[0:len(workBlock)])] = byte(b)
		}
		return blockDict
	}

	knownMsg := []byte{}
NEXT_CHARACTER:
	for {
		lenPadding := ((blockSize - 1) - len(knownMsg)) % blockSize
		if lenPadding < 0 {
			lenPadding += blockSize
		}
		padChunk := make([]byte, lenPadding)
		buf := C12EncryptionOracle(padChunk)

		// We want last blockSize-1 bytes of knownMsg
		//
		targetBlock := make([]byte, blockSize-1)
		offset := len(knownMsg) - (blockSize - 1)
		if offset < 0 {
			copy(targetBlock[-offset:], knownMsg)
		} else {
			copy(targetBlock, knownMsg[len(knownMsg)-(blockSize-1):])
		}

		blockDict := makeDict(targetBlock)

		chunks, slop := BytesToChunks(buf, blockSize)
		if len(slop) != 0 {
			panic(fmt.Sprintf("wtf - found slop %v", slop))
		}

		for _, chunk := range chunks {
			b, ok := blockDict[string(chunk)]
			if ok {
				knownMsg = append(knownMsg, b)
				//				t.Logf("MSG: %s\n", string(knownMsg))
				continue NEXT_CHARACTER
			}
		}
		break NEXT_CHARACTER
	}
	t.Logf("MSG: %s\n", string(knownMsg))
}

var C12FixedKey = RandomKey()

func C12EncryptionOracle(msg []byte) []byte {
	secret, err := DeBase64(`
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
`)
	if err != nil {
		panic(fmt.Sprintf("wtf - can't unbase64: %s", err))
	}
	msg = append(msg, secret...)
	return AESECBEncrypt(C12FixedKey, msg)
}

func TestS2C11(t *testing.T) {
	numTries := 50

	repeatedPlainText := make([]byte, AESBlockSize*10)

	for i := 0; i < numTries; i++ {
		buf, wasECB := C11EncryptionOracle(repeatedPlainText)
		got := HasDuplicateBlocks(buf, AESBlockSize)
		if got != wasECB {
			t.Errorf("Failed to guess on try %d", i)
		}
	}
	t.Logf("Ran %d tries", numTries)
}

func C11EncryptionOracle(msg []byte) ([]byte, bool) {
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
