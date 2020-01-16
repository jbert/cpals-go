package cpals

import "testing"

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

func TestS1C3(t *testing.T) {
	ctxtHexStr := HexStr("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	ctxt, _ := DeHex(ctxtHexStr)
	ptxt := SolveEnglishSingleByteXor(ctxt)
	t.Logf("MSG: %s\n", ptxt)
}
