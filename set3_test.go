package cpals

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestS3C17(t *testing.T) {
	blockSize := 16
	buf, iv := C17Encrypt()
	chunks, slop := BytesToChunks(buf, blockSize)
	if len(slop) != 0 {
		t.Fatalf("Slop from CBC !!?")
	}

	po := PaddingOracle(func(iv, buf []byte) bool {
		return C17PaddingGood(iv, buf)
	})
	var plainChunks [][]byte
	loopIV := iv
	for i, c := range chunks {
		plainChunk, err := po.AttackBlock(loopIV, c)
		if err != nil {
			t.Fatalf("Can't attack chunk %d: %s", i, err)
		}
		t.Logf("Got chunk: %s\n", plainChunk)
		plainChunks = append(plainChunks, plainChunk)
		loopIV = c
	}
	t.Logf("MSG: %s\n", bytes.Join(plainChunks, []byte{}))

	t.Logf("TODO - find the other texts")
}

var C17FixedKey = RandomKey()

func C17PaddingGood(iv, buf []byte) (paddingGood bool) {
	paddingGood = true
	defer func() {
		if r := recover(); r != nil {
			paddingGood = false
		}
	}()
	AESCBCDecrypt(C17FixedKey, iv, buf)
	return
}

func C17Encrypt() ([]byte, []byte) {
	plaintexts := []B64Str{
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
	}
	b64str := plaintexts[rand.Intn(len(plaintexts))]
	msg, err := DeBase64(b64str)
	if err != nil {
		panic("wtf")
	}

	iv := RandomKey()

	buf := AESCBCEncrypt(C17FixedKey, iv, msg)

	return buf, iv
}
