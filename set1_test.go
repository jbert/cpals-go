package cpals

import "testing"

func TestS1C1(t *testing.T) {
	testCases := []struct {
		hexStr   string
		dehexErr error
		b64Str   string
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
