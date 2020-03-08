package hmac

import (
	//	"crypto/sha1"
	"testing"

	"github.com/jbert/cpals-go/sha1"
)

func TestBasic(t *testing.T) {
	secretKey := []byte("YELLOW SUBMARINE")

	macKey := func(key, msg []byte) []byte {
		h := New(sha1.New, key)
		h.MustWrite(msg)
		return h.Sum(nil)
	}
	mac := func(msg []byte) []byte {
		return macKey(secretKey, msg)
	}
	bytesEqual := func(a, b []byte) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}

	msg := []byte("Once more unto the breach dear friends")
	digest := mac(msg)
	d2 := mac(msg)
	if !bytesEqual(digest, d2) {
		t.Fatalf("Digest is random...>")
	}
	t.Log("Digest is not random")

	notMsg := make([]byte, len(msg))
	copy(notMsg, msg)
	copy(notMsg[2:], []byte("ICE ICE BABY"))

	if bytesEqual(msg, notMsg) {
		t.Fatal("Messed up creating test data - didn't change")
	}
	if len(msg) != len(notMsg) {
		t.Fatal("Messed up creating test data - want same length")
	}
	t.Log("Can create test data")

	d2 = mac(notMsg)
	if bytesEqual(digest, d2) {
		t.Fatalf("msg and notMsg have same digest under same key")
	}
	t.Log("Diff messages have diff data")

	otherKey := []byte("wokka wokka")
	d2 = macKey(otherKey, msg)
	if bytesEqual(digest, d2) {
		t.Fatalf("msg has same digest with diff key")
	}
	t.Log("Diff keys with same message have diff data")

}
