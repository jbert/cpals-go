package cpals

import (
	"fmt"
	"testing"
)

func TestAESCBC(t *testing.T) {
	key := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	in := Hamlet
	if len(in)%AESBlockSize == 0 {
		t.Fatalf("Poor test - we want a non-blocksize text")
	}

	iv := RandomKey()
	got := AESCBCEncrypt(key, iv, in)
	if BytesEqual(got, in) {
		t.Fatalf("poor encryption...")
	}
	if len(got)%AESBlockSize != 0 {
		t.Fatalf("Encrypted msg not block-sized: %d", len(got))
	}

	out := AESCBCDecrypt(key, iv, got)
	if !BytesEqual(out, in) {
		t.Fatalf("poor en+decryption... %s != %s", string(out), string(in))
	}
	t.Log("Can encrypt and decrypt AES CBC")
}

func TestPKCSPadding(t *testing.T) {
	for i := 1; i < 3*AESBlockSize; i++ {
		buf := RandomBytes(i)
		padded := BytesPKCS7Pad(buf, AESBlockSize)
		if len(padded)%AESBlockSize != 0 {
			t.Fatal("Padding didn't get blocksize right")
		}
		if len(padded) == len(buf) {
			t.Fatal("Padding didn't add any size")
		}
		unpadded, err := BytesPKCS7UnPad(padded)
		if err != nil {
			t.Fatalf("Unpad failed: %s", err)
		}
		if !BytesEqual(unpadded, buf) {
			t.Fatalf("Pad+unpad broke msg")
		}
	}
}

func TestAESECB(t *testing.T) {
	key := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	in := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	expected := []byte{0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a}

	got := AESECBEncrypt(key, in)
	if BytesEqual(got, in) {
		t.Fatalf("poor encryption...")
	}
	if !BytesEqual(got[0:16], expected) {
		t.Fatalf("Didn't match vector got %v expected %v", got[0:16], expected)
	}

	out := AESECBDecrypt(key, got)
	if !BytesEqual(out, in) {
		t.Fatalf("poor en+decryption... %v != %v", out, in)
	}
	t.Log("Can encrypt and decrypt AES ECB")
}

func TestChunksTranspose(t *testing.T) {
	testCases := []struct {
		in       [][]byte
		expected [][]byte
	}{
		{
			[][]byte{[]byte("ABC"), []byte("DEF")},
			[][]byte{[]byte("AD"), []byte("BE"), []byte("CF")},
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%v", tc.in), func(t *testing.T) {
			got := ChunksTranspose(tc.in)
			if !ChunksEqual(got, tc.expected) {
				t.Fatalf("got %v expected %v", got, tc.expected)
			}
		})
	}
}

func TestBytesToChunks(t *testing.T) {
	testCases := []struct {
		buf            string
		size           int
		expectedChunks []string
		expectedSlop   string
	}{
		{"ABCDEFGHIJ", 2, []string{"AB", "CD", "EF", "GH", "IJ"}, ""},
		{"ABCDEFGHIJ", 3, []string{"ABC", "DEF", "GHI"}, "J"},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s: %d", tc.buf, tc.size), func(t *testing.T) {
			gotChunks, gotSlop := BytesToChunks([]byte(tc.buf), tc.size)
			if len(gotChunks) != len(tc.expectedChunks) {
				t.Fatalf("Wrong number of chunks: %d != %d", len(gotChunks), len(tc.expectedChunks))
			}
			for i := range gotChunks {
				if !BytesEqual(gotChunks[i], []byte(tc.expectedChunks[i])) {
					t.Fatalf("Chunk %d wrong: %v != %v", i, gotChunks[i], []byte(tc.expectedChunks[i]))
				}
			}
			if len(gotSlop) != len(tc.expectedSlop) {
				t.Fatalf("Wrong length of slop: %d != %d", len(gotSlop), len(tc.expectedSlop))
			}
		})
	}
}

func TestHammingDistance(t *testing.T) {
	a := []byte("this is a test")
	b := []byte("wokka wokka!!!")
	got, err := HammingDistance(a, b)
	if err != nil {
		t.Fatalf("Got error when shouldn't: %s", err)
	}
	expected := 37
	if got != expected {
		t.Fatalf("got %d expected %d", got, expected)
	}
	t.Logf("ok")
}

func TestByteLowerCase(t *testing.T) {
	testCases := []struct {
		in       byte
		expected byte
	}{
		{'A', 'a'},
		{'a', 'a'},
		{'F', 'f'},
		{'f', 'f'},
		{' ', ' '},
	}
	for _, tc := range testCases {
		got := ByteLowerCase(tc.in)
		if got != tc.expected {
			t.Errorf("Failed: %c != %c (%02X != %02X)", got, tc.expected, got, tc.expected)
		}
	}
}
