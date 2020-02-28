package diffie

import (
	"testing"

	"github.com/jbert/cpals-go"
)

func TestS5C34(t *testing.T) {
	aMessage := "Yo, what's up?"
	expectedReply := "Not much, you?"

	hs := NewHonestServer()
	hs.Replies = map[string]string{
		aMessage:       expectedReply,
		"ICE ICE BABY": "We don't do that here",
		"default":      "No hablo cop",
	}

	hc := NewHonestClient()
	hc.Connect(hs)

	wireMessage := hc.Encrypt(aMessage)
	if cpals.BytesEqual(wireMessage, []byte(aMessage)) {
		t.Fatalf("Encryption didn't do much")
	} else {
		t.Logf("Encryption changed bytes, must be good [%s] != [%s]", aMessage, string(wireMessage))
	}

	wireReply := hc.Send(wireMessage)
	reply := hc.Decrypt(wireReply)
	if cpals.BytesEqual(wireReply, []byte(reply)) {
		t.Fatalf("Decryption didn't do much")
	} else {
		t.Logf("Decryption changed bytes, must be good [%s] != [%s]", reply, string(wireReply))
	}

	if reply == expectedReply {
		t.Logf("Server received [%s] and replied [%s] as hoped", aMessage, reply)
	} else {
		t.Fatalf("Failed to get correct reply: got %s expected %s", reply, expectedReply)
	}

}
