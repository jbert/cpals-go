package cpals

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"
)

func TestS3C26(t *testing.T) {
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

func TestS3C25(t *testing.T) {
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
