package cpals

import (
	"fmt"
	"math/rand"
	"testing"
)

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
