package diffie

import (
	"testing"

	"github.com/jbert/cpals-go"
)

func TestS5C34(t *testing.T) {
	t.Run("HONEST", testHonest)
	t.Run("MITM", testMITM)
}

func testMITM(t *testing.T) {
	t.Log("Test MITM")
	hs := NewHonestServer()
	hc := NewHonestClient()
	mitm := NewEvilMITM()

	// This is what MITM can do ...
	mitm.Connect(hs)
	hc.Connect(mitm)

	secretMessages := testComms(t, hc, hs)

	snoopedMsgs := mitm.SnoopedMessages()
	for _, secretMsg := range secretMessages {
		found := false
		for _, snoopedMsg := range snoopedMsgs {
			if snoopedMsg == secretMsg {
				t.Logf("Snooped message: %s", secretMsg)
				found = true
			}
		}
		if !found {
			t.Fatalf("Didn't snoop message: %s", secretMsg)
		}
	}
}

func testHonest(t *testing.T) {
	t.Log("Test HONEST")
	hs := NewHonestServer()

	hc := NewHonestClient()
	hc.Connect(hs)
	testComms(t, hc, hs)
}

func testComms(t *testing.T, hc *HonestClient, hs *HonestServer) []string {
	secretMessages := []string{}

	aMessage := "Yo, what's up?"
	expectedReply := "Not much, you?"

	hs.Replies = map[string]string{
		aMessage:       expectedReply,
		"ICE ICE BABY": "We don't do that here",
		"default":      "No hablo cop",
	}

	wireMessage := hc.Encrypt(aMessage)
	secretMessages = append(secretMessages, aMessage)
	if cpals.BytesEqual(wireMessage, []byte(aMessage)) {
		t.Fatalf("Encryption didn't do much")
	} else {
		t.Logf("Encryption changed bytes, must be good [%s] != [%s]", aMessage, string(wireMessage))
	}

	wireReply := hc.Send(wireMessage)
	reply := hc.Decrypt(wireReply)
	secretMessages = append(secretMessages, reply)
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

	return secretMessages
}
