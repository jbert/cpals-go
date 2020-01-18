package cpals

import (
	"fmt"
	"testing"
)

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
