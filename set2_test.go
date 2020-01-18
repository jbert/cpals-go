package cpals

import (
	"fmt"
	"testing"
)

func TestS2C9(t *testing.T) {
	blockSize := 8

	testCases := []struct {
		in       []byte
		expected []byte
	}{
		{
			[]byte{0, 0, 0, 0, 0, 0, 0, 0},
			[]byte{0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 8, 8, 8, 8, 8, 8},
		},
		{
			[]byte{0, 0, 0, 0, 0, 0, 0},
			[]byte{0, 0, 0, 0, 0, 0, 0, 1},
		},
		{
			[]byte{0, 0, 0, 0, 0, 0},
			[]byte{0, 0, 0, 0, 0, 0, 2, 2},
		},
		{
			[]byte{0, 0, 0},
			[]byte{0, 0, 0, 5, 5, 5, 5, 5},
		},
		{
			[]byte{},
			[]byte{8, 8, 8, 8, 8, 8, 8, 8},
		},
		{
			[]byte{0},
			[]byte{0, 7, 7, 7, 7, 7, 7, 7},
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%v", tc.in), func(t *testing.T) {
			got := BytesPKCS7Pad(tc.in, blockSize)
			if !BytesEqual(got, tc.expected) {
				t.Fatalf("got %v expected %v", got, tc.expected)
			}
		})
	}
}
