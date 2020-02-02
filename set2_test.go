package cpals

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

func TestS2C16(t *testing.T) {
	// Turn a panic into an error
	decryptor := func(buf []byte) (isAdmin bool, err error) {
		defer func() {
			r := recover()
			if r != nil {
				err = errors.New(r.(string))
			}
		}()
		isAdmin = C16Decode(buf)
		return
	}

	C16Encode := Oracle(C16EncodeFunc)

	naiveAttempt := []byte(";admin=true;")
	buf := C16Encode(naiveAttempt)
	isAdmin, err := decryptor(buf)
	if err != nil {
		t.Fatalf("Got error decrypting legit msg: %s", err)
	}
	t.Log("Can encrypt naive attempt")
	if isAdmin {
		t.Fatalf("Got admin with naive userdata")
	}
	t.Log("Didn't get admin with naive attempt")
	isAdmin, err = decryptor([]byte{1, 2, 3, 4})
	if err == nil {
		t.Fatalf("Didn't get error for bad padding")
	}
	t.Log("Got error return for bad padding")

	blockSize := C16Encode.FindBlockSize()
	t.Logf("Blocksize is %d", blockSize)

	/*
		// How much padding do we add to spill to a block?
		var paddingOffset int
		lastLen := 0
		for i := 0; i < blockSize; i++ {
			buf = C16Encode(make([]byte, i))
			if lastLen != 0 && len(buf) != lastLen {
				paddingOffset = i
			}
			lastLen = len(buf)
		}
		if paddingOffset == 0 {
			t.Fatalf("Can't find padding offset")

		}
		t.Logf("Padding offset: %d", paddingOffset)
	*/
	// There is a bit pattern which, when put into the first of these
	// two blocks, will put the desired string into the second block

	// So for each byte of the first block, we find which value will put a zero
	// into the second block

	// We can do this because we know when the relevant padding byte is correct

	var attackBlock []byte
	decodeMsg := func(desiredMsg []byte) (bool, error) {

		// Get a ciphertext of at least two blocks
		twoBlockBuf := C16Encode(NewBytes(2*blockSize, 0))

		// Replace the first block with our attack block, XORd with the desired message
		// This will XORd with our desired message with the following block
		desired := make([]byte, blockSize)
		copy(desired, desiredMsg)
		desired, err = Xor(desired, attackBlock)
		if err != nil {
			panic("Can't XOR same size bufs?")
		}
		copy(twoBlockBuf, desired)

		// And we make the following block zeros, so XORing with our msg gives our msg
		copy(twoBlockBuf[blockSize:], make([]byte, blockSize))

		return decryptor(twoBlockBuf)
	}

	padOracle := PaddingOracle(func(buf []byte) bool {
		_, err = decryptor(buf)
		return err == nil
	})
	attackBlock, err = padOracle.AttackBlock(make([]byte, blockSize))
	if err != nil {
		t.Fatalf("Can't construct attack block: %s", err)
	}

	t.Logf("About to decrypt target")
	isAdmin, err = decodeMsg([]byte(";admin=true;"))
	if err != nil {
		t.Fatalf("Error on the descrypt: %s", err)
	} else {
		if isAdmin {
			t.Logf("Woo! Got admin")
		} else {
			t.Fatalf("I don't wna to live in this world any more")
		}
	}
}

var C16FixedKey = RandomKey()

func C16Decode(buf []byte) bool {
	msg := AESCBCDecrypt(C16FixedKey, ZeroIV, buf)
	return strings.Contains(string(msg), ";admin=true;")
}

func C16EncodeFunc(userData []byte) []byte {
	userData = bytes.ReplaceAll(userData, []byte(";"), []byte("%3B"))
	userData = bytes.ReplaceAll(userData, []byte("="), []byte("%3D"))
	msg := []byte("comment1=cooking%20MCs;userdata=")
	msg = append(msg, userData...)
	msg = append(msg, []byte(";comment2=%20like%20a%20pound%20of%20bacon")...)
	return AESCBCEncrypt(C16FixedKey, ZeroIV, []byte(msg))
}

func TestS2C15(t *testing.T) {
	testCases := []struct {
		in   string
		good bool
	}{
		{"ICE ICE BABY\x04\x04\x04\x04", true},
		{"ICE ICE BABY\x05\x05\x05\x05", false},
		{"ICE ICE BABY\x01\x02\x03\x04", false},
	}

	for _, tc := range testCases {
		_, err := BytesPKCS7UnPad([]byte(tc.in))
		if err == nil != tc.good {
			t.Errorf("Failed: %s got err %s", tc.in, err)
		}
	}
	t.Logf("PKCS7 unpad shows correct errors")
}

func TestS2C14(t *testing.T) {
	//	...as for C12 but we need to loop when biulding the dict so we get blockSize candidates for each byte...
	C14EncryptionOracle := Oracle(C14EncryptionOracleFunc)

	blockSize := C14EncryptionOracle.FindBlockSize()
	t.Logf("Enc oracle has block size: %d", blockSize)
	isECB := C14EncryptionOracle.IsECB(blockSize)
	t.Logf("Enc oracle is ECB: %v", isECB)

	blockAfterDuplicates := func(buf []byte, blockSize int) (bool, []byte) {
		chunks, _ := BytesToChunks(buf, blockSize)
		var lastChunk []byte
		lastDup := false
		for _, c := range chunks {
			if lastDup {
				return true, c
			}
			if lastChunk != nil {
				if BytesEqual(lastChunk, c) {
					lastDup = true
				}
			}
			lastChunk = c
		}
		return false, nil
	}

	makeDict := func(targetBlock []byte) map[string]byte {
		blockDict := make(map[string]byte)
		workBlock := make([]byte, len(targetBlock)+1)
		copy(workBlock, targetBlock)
		for b := 0; b <= 0xff; b++ {
		FIND_DUP:
			for {
				workBlock[len(workBlock)-1] = byte(b)

				// Prefix work block with 2 identical blocks
				// We know if we get identical blocks in output, we were aligned
				chosenMsg := NewBytes(blockSize, 'B')
				chosenMsg = append(chosenMsg, NewBytes(2*blockSize, 'A')...)
				chosenMsg = append(chosenMsg, workBlock...)
				buf := C14EncryptionOracle(chosenMsg)

				// If we t have duplicates, we want
				hasDuplicate, blockAfter := blockAfterDuplicates(buf, blockSize)
				if hasDuplicate {
					blockDict[string(blockAfter)] = byte(b)
					break FIND_DUP
				}
			}
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

		// Loop until we see duplicate blocks
		var buf []byte
		chosenMsg := NewBytes(blockSize, 'B')
		chosenMsg = append(chosenMsg, NewBytes(2*blockSize, 'A')...)
		chosenMsg = append(chosenMsg, padChunk...)
	TRY_ALIGNMENT:
		for {
			buf = C14EncryptionOracle(chosenMsg)
			if HasDuplicateBlocks(buf, blockSize) {
				break TRY_ALIGNMENT
			}
		}

		// We want last blockSize-1 bytes of knownMsg
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
				//				t.Logf("%d MSG: %s\n", len(knownMsg), string(knownMsg))
				continue NEXT_CHARACTER
			}
		}
		break NEXT_CHARACTER
	}
	t.Logf("MSG: %s\n", string(knownMsg))
}

func C14EncryptionOracleFunc(msg []byte) []byte {
	prefix := RandomRandomBytes(10, 20)
	msg = append(prefix, msg...)
	//	fmt.Printf("prefix %d msg len %d mod %d\n", len(prefix), len(msg), len(msg)%16)
	buf := C12EncryptionOracleFunc(msg)
	//	fmt.Printf("P %4d: %s\nC %4d: %s\n", len(msg), EnHex(msg), len(buf), EnHex(buf))
	return buf
}

func TestS2C13(t *testing.T) {
	// Want to switch out a block 'userPADDING' with 'admin&'
	// have an email ending in 'admin', so get a sep at end
	// save blocks at all offsets

	cryptor := func(buf []byte) []byte {
		return C13EncryptedProfileFor(string(buf))
	}
	blockSize, pkcsFullPadBlock := FindBlockSizeAndFullPadBlock(cryptor)
	t.Logf("block size is %d\n", blockSize)

	//target := []byte("admin")
	target := []byte("admin&foo=123456")
	savedBlocks := make([][]byte, 0)
	for i := 0; i < blockSize; i++ {
		in := make([]byte, i+len(target))
		copy(in[i:], target)
		buf := C13EncryptedProfileFor(string(in))
		chunks, slop := BytesToChunks(buf, blockSize)
		if len(slop) != 0 {
			panic("badness")
		}
		for _, c := range chunks {
			savedBlocks = append(savedBlocks, c)
		}
	}

	t.Logf("Got %d saved blocks", len(savedBlocks))

	var up UserProfile
	var err error
	found := false
	email := "evil@example.com"
FINISHED:
	for i := 0; i < blockSize; i++ {
		playBuf := C13EncryptedProfileFor(email)
		playBuf = append(playBuf, pkcsFullPadBlock...)
		for _, c := range savedBlocks {
			copy(playBuf[len(playBuf)-2*blockSize:], c)
			up, err = C13DecryptProfile(playBuf)
			if err != nil {
				continue
			}
			if up.role == "admin" {
				found = true
				break FINISHED
			}
		}
		email = "A" + email
	}

	if found {
		t.Logf("<voice>We're in</voice> Got profile: %s", up.Encode())
	} else {
		t.Error("Not found :-(")
	}
}

var C13FixedKey = RandomKey()

func C13DecryptProfile(buf []byte) (up UserProfile, err error) {
	defer func() {
		r := recover()
		if r != nil {
			err = fmt.Errorf("PANIC: %v", r)
		}
	}()
	encProfile := AESECBDecrypt(C13FixedKey, buf)
	up, err = ParseProfile(string(encProfile))
	if err != nil {
		return up, fmt.Errorf("Can't parse profile: %w", err)
	}
	return up, nil
}

func C13EncryptedProfileFor(email string) []byte {
	return AESECBEncrypt(C13FixedKey, []byte(ProfileFor(email)))
}

func TestS2C12(t *testing.T) {
	C12EncryptionOracle := Oracle(C12EncryptionOracleFunc)
	blockSize := C12EncryptionOracle.FindBlockSize()
	t.Logf("Enc oracle has block size: %d", blockSize)
	isECB := C12EncryptionOracle.IsECB(blockSize)
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

func C12EncryptionOracleFunc(msg []byte) []byte {
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
