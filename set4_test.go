package cpals

import (
	"bytes"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

func TestS4C28(t *testing.T) {

	msg := Hamlet
	digest := PrefixMac(YellowKey, msg)
	d2 := PrefixMac(YellowKey, msg)
	if !BytesEqual(digest, d2) {
		t.Fatalf("Digest is random...>")
	}
	t.Log("Digest is not random")

	notHamlet := make([]byte, len(Hamlet))
	copy(notHamlet, Hamlet)
	copy(notHamlet[10:], []byte("ICE ICE BABY"))

	if BytesEqual(Hamlet, notHamlet) {
		t.Fatal("Messed up creating test data - didn't change")
	}
	if len(Hamlet) != len(notHamlet) {
		t.Fatal("Messed up creating test data - want same length")
	}
	t.Log("Can create test data")

	d2 = PrefixMac(YellowKey, notHamlet)
	if BytesEqual(digest, d2) {
		t.Fatalf("Hamlet and notHamlet have same digest under same key")
	}
	t.Log("Diff messages have diff data")

	randomKey := RandomKey()
	d2 = PrefixMac(randomKey, Hamlet)
	if BytesEqual(digest, d2) {
		t.Fatalf("Hamlet has same digest with diff key")
	}
	t.Log("Diff keys with same message have diff data")

}

func TestS4C27(t *testing.T) {
	blockSize := 16

	secretPlainText := Hamlet

	if ok, err := isAscii(secretPlainText); !ok {
		t.Fatalf("This isn't going to work...: %s", err)
	}
	buf := C27EncodeFunc(secretPlainText)
	_, err, errBuf := C27Decode(buf)
	if err != nil {
		t.Fatalf("Can't decrypt: %s", err)
	}

	attackBuf := make([]byte, len(buf))
	copy(attackBuf, buf)
	zeroBlock := make([]byte, blockSize)
	// C_2 = 0
	copy(attackBuf[blockSize:], zeroBlock)
	// C_3 = C_1
	copy(attackBuf[blockSize*2:], buf[0:blockSize])

	_, err, errBuf = C27Decode(attackBuf)
	if err == nil {
		t.Fatalf("Setting zero block didn't produce non-ascii - wtf?")
	}
	t.Logf("(expected) Decode err: %s", err)

	// errBuf is plaintext of this decrypt
	// Attack_P_1 == IV XOR Real_P_1 == KEY XOR Real_P_1
	// Attack_P_3 == 0 XOR Real_P_1
	// So:
	// Key == Attack_P_1 XOR Attack_P_3
	//	t.Logf("errbuf\n%s\n", BytesHexBlocks(errBuf[0:blockSize*3], blockSize))
	foundKey, err := Xor(errBuf[0:blockSize], errBuf[blockSize*2:blockSize*3])
	if err != nil {
		t.Fatalf("blocksize mismatch")
	}

	t.Logf("Key is %s", BytesHexBlocks(foundKey, blockSize))

	recoveredPlainText := AESCBCDecrypt(foundKey, foundKey, buf)
	t.Logf("Recovered: %s\n", string(recoveredPlainText))
}

var C27FixedKey = RandomKey()

func isAscii(buf []byte) (bool, error) {
	for i, b := range buf {
		if b&0x80 != 0 {
			return false, fmt.Errorf("Byte %X is %02X - non-ascii", i, b)
		}
	}
	return true, nil
}

func C27Decode(buf []byte) (bool, error, []byte) {
	msg := AESCBCDecryptMaybePadding(C27FixedKey, C27FixedKey, buf, false)
	//	fmt.Printf("BUF: %s\n", BytesHexBlocks(msg, 16))
	//	fmt.Printf("BUF: %s\n", msg)
	if ok, err := isAscii(msg); !ok {
		return ok, err, msg
	}

	return strings.Contains(string(msg), ";admin=true;"), nil, nil
}

func C27EncodeFunc(userData []byte) []byte {
	userData = bytes.ReplaceAll(userData, []byte(";"), []byte("%3B"))
	userData = bytes.ReplaceAll(userData, []byte("="), []byte("%3D"))
	msg := []byte("comment1=cooking%20MCs;userdata=")
	msg = append(msg, userData...)
	msg = append(msg, []byte(";comment2=%20like%20a%20pound%20of%20bacon")...)
	// Re-use key as IV - bad
	return AESCBCEncrypt(C27FixedKey, C27FixedKey, []byte(msg))
}

func TestS4C26(t *testing.T) {
	desired := []byte(";admin=true;")
	chosenByte := byte('A')
	chosenPlainText := NewBytes(len(desired), chosenByte)
	ctxt := C26EncodeFunc(chosenPlainText)

	gotAdmin := false
POS:
	for offset := 0; offset < len(ctxt)-len(desired); offset++ {
		attack := make([]byte, len(ctxt))
		copy(attack, ctxt)
		for i := 0; i < len(desired); i++ {
			attack[offset+i] ^= chosenByte ^ desired[i]
		}
		gotAdmin = C26Decode(attack)
		if gotAdmin {
			break POS
		}
	}

	if gotAdmin {
		t.Fatalf("Woo hoo! got admin")
	} else {
		t.Fatalf("Failed to get admin :-(")
	}

}

var C26FixedKey = RandomKey()
var C26FixedNonce = int64(rand.Uint64())

func C26Decode(buf []byte) bool {
	msg := AESCTR(C26FixedKey, C26FixedNonce, buf)
	return bytes.Contains(msg, []byte(";admin=true;"))
}

func C26EncodeFunc(userData []byte) []byte {
	userData = bytes.ReplaceAll(userData, []byte(";"), []byte("%3B"))
	userData = bytes.ReplaceAll(userData, []byte("="), []byte("%3D"))
	msg := []byte("comment1=cooking%20MCs;userdata=")
	msg = append(msg, userData...)
	msg = append(msg, []byte(";comment2=%20like%20a%20pound%20of%20bacon")...)
	return AESCTR(C26FixedKey, C26FixedNonce, []byte(msg))
}

func TestS4C25(t *testing.T) {
	buf := MustLoadB64("25.txt")
	secretPlainText := AESECBDecrypt(YellowKey, buf)

	disk := NewC25Disk(RandomKey(), secretPlainText)

	t.Log("We can see the encrypted disk")
	originalCipherText := disk.CipherText()
	//	t.Logf("CT: %s", BytesHexBlocks(originalCipherText, 16))
	t.Log("If we write zeros all over it, the disk is now the keystream")

	disk.Edit(0, make([]byte, len(originalCipherText)))
	ks := disk.CipherText()
	t.Log("So plaintext is easy...")
	//	t.Logf("KS: %s", BytesHexBlocks(ks, 16))

	recoveredPlainText, err := Xor(originalCipherText, ks)
	if err != nil {
		t.Fatalf("wtf")
	}
	if !BytesEqual(recoveredPlainText, secretPlainText) {
		t.Fatalf("Failed to recover plaintext: %s", BytesHexBlocks(recoveredPlainText, 16))
	}
	t.Logf("Woo hoo - recovered\n%s\n", string(recoveredPlainText))
}

type C25Disk struct {
	key   []byte
	data  []byte
	nonce int64
}

func NewC25Disk(key []byte, plainText []byte) *C25Disk {
	nonce := int64(rand.Uint64())
	d := &C25Disk{
		key:   key,
		nonce: nonce,
		data:  make([]byte, len(plainText)),
		//		data:  AESCTR(key, nonce, plainText),
	}
	d.Edit(0, plainText)
	return d
}

func (d *C25Disk) Edit(offset int, plainText []byte) {
	upTo := offset + len(plainText)
	ks := AESCTRKeyStream(d.key, d.nonce, upTo)
	buf, err := Xor(ks[upTo-len(plainText):], plainText)
	if err != nil {
		panic("wtf")
	}
	n := copy(d.data[offset:], buf)
	if n != len(buf) {
		panic(fmt.Sprintf("Only copied %d bytes, not %d", n, len(buf)))
	}
}

func (d *C25Disk) CipherText() []byte {
	ret := make([]byte, len(d.data))
	copy(ret, d.data)
	return ret
}
