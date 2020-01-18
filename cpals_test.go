package cpals

import (
	"fmt"
	"testing"
)

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
