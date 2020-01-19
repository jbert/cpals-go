package cpals

import (
	"fmt"
	"sort"
	"testing"
)

func TestS1C8(t *testing.T) {
	fname := "8.txt"
	lines, err := LoadLines(fname)
	if err != nil {
		t.Fatalf("Can't load lines from file [%s]: %s", fname, err)
	}

	blockSize := 16
	for i, l := range lines {
		buf, _ := DeHex(HexStr(l))
		dup := BytesFindDuplicateBlock(buf, blockSize)
		if dup != nil {
			fmt.Printf("Line %d has duplicate blocks\n", i)
		}
	}
}

func TestS1C7(t *testing.T) {
	fname := "7.txt"
	buf := MustLoadB64(fname)
	dst := AESECBDecrypt(YellowKey, buf)
	/*
		aes, err := aes.NewCipher(key)
		if err != nil {
			t.Fatalf("Can't create aes cipher: %s", err)
		}
		dec := NewECBDecrypter(aes)

		dst := make([]byte, len(buf))
		dec.CryptBlocks(dst, buf)
	*/
	t.Logf("Msg:\n%s\n", dst)
}

func TestS1C6(t *testing.T) {
	fname := "6.txt"
	buf, err := LoadB64(fname)
	if err != nil {
		t.Fatalf("Can't load base64 from %s: %s", fname, err)
	}
	//	t.Logf("Read buf: %v", buf)

	keySizes := GuessXorKeySize(buf)

	type sizeScore struct {
		keySize int
		score   float64
		msg     []byte
	}

	numToExamine := 10
	sizeScores := make([]sizeScore, numToExamine)
	for i, keySize := range keySizes[0:numToExamine] {
		//		t.Logf("Key size: %d", keySize)
		chunks, _ := BytesToChunks(buf, keySize)
		chunks = ChunksTranspose(chunks)
		if len(chunks) != keySize {
			t.Fatalf("WTF")
		}
		key := make([]byte, keySize)
		for i := range key {
			_, _, b := SolveEnglishSingleByteXor(chunks[i])
			key[i] = b
		}
		msg := XorKey(buf, key)
		englishScore := EnglishScore(msg)
		sizeScores[i] = sizeScore{keySize, englishScore, msg}
		//		t.Logf("Keysize: %d Score %f\n%s\n", sizeScores[i].keySize, sizeScores[i].score, sizeScores[i].msg)
	}

	sort.Slice(sizeScores, func(i, j int) bool {
		return sizeScores[i].score > sizeScores[j].score
	})
	t.Logf("Keysize: %d Score: %f\n%s\n", sizeScores[0].keySize, sizeScores[0].score, sizeScores[0].msg)
}

func TestS1C5(t *testing.T) {
	msg := `Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`
	key := "ICE"
	buf := XorKey([]byte(msg), []byte(key))
	hexBuf := EnHex(buf)
	expectedHexBuf := HexStr(`0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f`)
	if !hexBuf.Equals(expectedHexBuf) {
		t.Errorf("Got %s expected %s", hexBuf, expectedHexBuf)
	}
	t.Log("Encrypted correctly")
}

func TestS1C4(t *testing.T) {
	fname := "4.txt"
	lines, err := LoadLines(fname)
	if err != nil {
		t.Fatalf("Can't load %s: %s", fname, err)
	}

	bestScore := 0.0
	var bestMsg []byte
	for _, l := range lines {
		buf, _ := DeHex(HexStr(l))
		msg, score, _ := SolveEnglishSingleByteXor(buf)
		if score > bestScore {
			bestMsg = msg
			bestScore = score
		}
	}
	t.Logf("MSG: %s\n", bestMsg)
}

func TestS1C3(t *testing.T) {
	bufHexStr := HexStr("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	buf, _ := DeHex(bufHexStr)
	msg, _, _ := SolveEnglishSingleByteXor(buf)
	t.Logf("MSG: %s\n", msg)
}

func TestS1C2(t *testing.T) {
	aHexStr := HexStr("1c0111001f010100061a024b53535009181c")
	bHexStr := HexStr("686974207468652062756c6c277320657965")
	a, _ := DeHex(aHexStr)
	b, _ := DeHex(bHexStr)

	got, err := Xor(a, b)
	if err != nil {
		t.Fatalf("Got error: %s", err)
	}
	expectedHex := HexStr("746865206b696420646f6e277420706c6179")
	expected, _ := DeHex(expectedHex)
	if !BytesEqual(got, expected) {
		t.Fatalf("Got [%s] expected [%s]", got, expected)
	}
	t.Logf("Got: %s\n", got)
}

func TestS1C1(t *testing.T) {
	testCases := []struct {
		hexStr   HexStr
		dehexErr error
		b64Str   B64Str
	}{
		{
			"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d",
			nil,
			"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
		},
	}

	for _, tc := range testCases {
		str, err := DeHex(tc.hexStr)
		if tc.dehexErr != err {
			t.Fatalf("Didn't get correct error return [%s] != [%s]", tc.dehexErr, err)
		}
		t.Logf("Secret str is [%s]", str)
		b64Str := Base64(str)
		if b64Str != tc.b64Str {
			t.Fatalf("Didn't get correct base64 str [%s] != [%s]", tc.b64Str, b64Str)
		}
	}
}
