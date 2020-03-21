package diffie

import (
	"testing"

	"github.com/jbert/cpals-go"
)

func TestS5C35(t *testing.T) {
	var m *EvilMITMG

	//	t.Run("HONEST", testHonest)
	mitm := NewEvilMITMG(m.One())
	t.Run("MITM g=1", func(t *testing.T) { testMITM(t, mitm, true) })

	mitm = NewEvilMITMG(m.P())
	t.Run("MITM g=nistP", func(t *testing.T) { testMITM(t, mitm, true) })

	mitm = NewEvilMITMG(m.PMinus1())
	t.Run("MITM g=nistP-1", func(t *testing.T) { testMITM(t, mitm, true) })
}

func TestS5C34(t *testing.T) {
	t.Run("HONEST", testHonest)
	mitm := NewEvilMITM()
	t.Run("MITM", func(t *testing.T) { testMITM(t, mitm, false) })
}

func testMITM(t *testing.T, mitm MITM, senderOnly bool) {
	t.Log("Test MITM")
	hs := NewHonestServer()
	hc := NewHonestClient()

	// This is what MITM can do ...
	mitm.Connect(hs)
	hc.Connect(mitm)

	secretMessages := testComms(t, hc, hs, senderOnly)

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
	testComms(t, hc, hs, false)
}

func testComms(t *testing.T, hc *HonestClient, hs *HonestServer, senderOnly bool) []string {
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
	if !senderOnly {
		secretMessages = append(secretMessages, reply)
	}
	if cpals.BytesEqual(wireReply, []byte(reply)) {
		t.Fatalf("Decryption didn't do much")
	} else {
		t.Logf("Decryption changed bytes, must be good [%s] != [%s]", reply, string(wireReply))
	}

	if !senderOnly {
		if reply == expectedReply {
			t.Logf("Server received [%s] and replied [%s] as hoped", aMessage, reply)
		} else {
			t.Fatalf("Failed to get correct reply: got %s expected %s", reply, expectedReply)
		}
	}

	return secretMessages
}
