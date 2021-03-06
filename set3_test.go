package cpals

import (
	"bytes"
	"errors"
	"math"
	"math/rand"
	"sort"
	"testing"
	"time"
)

func TestS3C24(t *testing.T) {
	msg := []byte("We wanna get loaded, we wanna party")
	seed := uint32(1234)
	buf := MTStream(seed, []byte(msg))
	if BytesEqual(msg, buf) {
		t.Fatalf("Encryption not very successful")
	}
	out := MTStream(seed, []byte(buf))
	if !BytesEqual(msg, out) {
		t.Fatalf("Can't encrypt/decrypt cycle")
	}
	t.Logf("Twerks")

	secretSeed := uint16(rand.Uint32())
	chosenPlainText := NewBytes(32, 'A')
	buf = C24Encrypt(secretSeed, chosenPlainText)

	var foundSeed uint16
	found := false
	for seed := 0; seed <= math.MaxUint16; seed++ {
		msg := MTStream(uint32(seed), buf)
		if bytes.HasSuffix(msg, chosenPlainText) {
			foundSeed = uint16(seed)
			found = true
		}
	}
	if !found {
		t.Fatalf("Didn't find seed")
	}
	if foundSeed != secretSeed {
		t.Fatalf("Found wrong seed got %d expected %d", foundSeed, secretSeed)
	}
	t.Logf("Found the seed!: %d", foundSeed)

	t.Logf(`TODO: unclear on the password reset token
Should it be:
- identify if the token is/contains the first N bytes of an MT stream from recent epoch?
- or try MTStream decrypt with recent epoch streams, but look for some structure (email?)
`)
}

func C24Encrypt(seed uint16, msg []byte) []byte {
	prefix := RandomRandomBytes(10, 20)
	msg = append(prefix, msg...)
	return MTStream(uint32(seed), msg)
}

func TestS3C23(t *testing.T) {
	mt := NewMT()
	randSeed := rand.Uint32()
	mt.Init(randSeed)

	randNumVals := rand.Intn(1000)
	for i := 0; i < randNumVals; i++ {
		_ = mt.ExtractNumber()
	}

	stateSize := 624
	observations := make([]uint32, stateSize)
	for i := range observations {
		observations[i] = mt.ExtractNumber()
	}

	clone := mt.CloneFromObservations(observations)

	numTests := 100
	for i := 0; i < numTests; i++ {
		expected := mt.ExtractNumber()
		got := clone.ExtractNumber()
		if got != expected {
			t.Fatalf("got %d expected %d on try %d", got, expected, i)
		}
	}
	t.Logf("Did it! cloned the rand")
}

func TestS3C22(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping sleeping test")
	}
	unixNow := time.Now().Unix()

	mt := NewMT()

	randSeconds := rand.Intn(10) + 5
	t.Logf("Sleeping for %d secs", randSeconds)
	time.Sleep(time.Second * time.Duration(randSeconds))

	actualSeed := uint32(unixNow)
	mt.Init(actualSeed)

	randSeconds = rand.Intn(10) + 5
	t.Logf("Sleeping for %d secs", randSeconds)
	time.Sleep(time.Second * time.Duration(randSeconds))

	val := mt.ExtractNumber()

	guessedSeed, err := C22GuessSeed(val)
	if err != nil {
		t.Fatalf("Problem finding: %s", err)
	}
	if guessedSeed == actualSeed {
		t.Logf("Woo! guessed the seed was %d", guessedSeed)
	} else {
		t.Fatalf("Your code is bad and you should feel bad. %d != %d", guessedSeed, actualSeed)
	}
}

func C22GuessSeed(seenV uint32) (uint32, error) {
	unixNow := uint32(time.Now().Unix())
	for i := 0; i < 1000; i++ {
		trySeed := unixNow - uint32(i)
		mt := NewMT()
		mt.Init(trySeed)
		for j := 0; j < 100; j++ {
			v := mt.ExtractNumber()
			if v == seenV {
				return trySeed, nil
			}
		}
	}

	return 0, errors.New("Can't find it")
}

func TestS3C21(t *testing.T) {
	expected := []uint32{
		2357136044,
		2546248239,
		3071714933,
		3626093760,
		2588848963,
		3684848379,
		2340255427,
		3638918503,
		1819583497,
		2678185683,
	}

	mt := NewMT()
	mt.Init(0)
	for i := 0; i < 10; i++ {
		n := mt.ExtractNumber()
		if n != expected[i] {
			t.Fatalf("Wrong value for %d: got %d expected %d", i, n, expected[i])
		}
		t.Logf("%d: N %d\n", i, n)
	}
}

func TestS3C20(t *testing.T) {
	lines, err := LoadLines("20.txt")
	if err != nil {
		t.Fatalf("Can't load lines: %s", err)
	}
	var b64str []B64Str
	for _, l := range lines {
		b64str = append(b64str, B64Str(l))
	}
	ctxts := C19CryptMsgs(t, b64str)
	attackRepeatedNonce(t, ctxts)
}

func TestS3C19(t *testing.T) {
	b64msgs := []B64Str{
		"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
		"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
		"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
		"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
		"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
		"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
		"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
		"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
		"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
		"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
		"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
		"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
		"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
		"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
		"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
		"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
		"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
		"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
		"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
		"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
		"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
		"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
		"U2hlIHJvZGUgdG8gaGFycmllcnM/",
		"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
		"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
		"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
		"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
		"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
		"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
		"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
		"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
		"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
		"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
		"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
		"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
		"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
		"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
		"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
		"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
		"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
	}

	ctxts := C19CryptMsgs(t, b64msgs)
	t.Logf("Loaded %d ctxts", len(ctxts))

	attackRepeatedNonce(t, ctxts)
}

func attackRepeatedNonce(t *testing.T, ctxts [][]byte) {

	maxLen := 0
	for _, ct := range ctxts {
		if len(ct) > maxLen {
			maxLen = len(ct)
		}
	}

	keyStream := make([]byte, maxLen)

	// We wnat to guess the keystream (then use it to XOR-decrypt)

	// A number of things to try:
	// - ASCII ^ ASCII has bit7 zero (so can get high bit of all KS bytes)
	// - for each pos, run english score

	for i := 0; i < maxLen; i++ {
		var msg []byte
		for _, ct := range ctxts {
			if len(ct) > i {
				msg = append(msg, ct[i])
			}
		}

		var bestScore float64
		var bestB byte
		for b := 0; b < 256; b++ {
			score := EnglishScore(XorByte(msg, byte(b)))
			if score > bestScore {
				bestScore = score
				bestB = byte(b)
			}
		}
		keyStream[i] = bestB
	}

	for i, ct := range ctxts {
		msg, err := Xor(ct, keyStream[:len(ct)])
		if err != nil {
			panic("whoops")
		}
		t.Logf("%d: %s\n", i, msg)
	}

	t.Logf("DONE!")
}

func C19CryptMsgs(t *testing.T, b64msgs []B64Str) [][]byte {
	key := RandomKey()
	nonce := int64(0)

	var cipherTexts [][]byte
	for _, b64str := range b64msgs {
		msg, err := DeBase64(b64str)
		if err != nil {
			t.Fatalf("wtf: %s", err)
		}
		buf := AESCTR(key, nonce, msg)
		cipherTexts = append(cipherTexts, buf)
	}
	return cipherTexts
}

func TestS3C18(t *testing.T) {
	buf, _ := DeBase64("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	nonce := int64(0)
	msg := AESCTR(YellowKey, nonce, buf)
	t.Logf("MSG: %s\n", msg)
}

func TestS3C17(t *testing.T) {
	found := make(map[string]bool)

	blockSize := 16

	loopsWithoutFindingNew := 0
	for loopsWithoutFindingNew < 100 {
		buf, iv := C17Encrypt()
		chunks, slop := BytesToChunks(buf, blockSize)
		if len(slop) != 0 {
			t.Fatalf("Slop from CBC !!?")
		}

		po := PaddingOracle(func(iv, buf []byte) bool {
			return C17PaddingGood(iv, buf)
		})
		var plainChunks [][]byte
		loopIV := iv
		for i, c := range chunks {
			plainChunk, err := po.AttackBlock(loopIV, c)
			if err != nil {
				t.Fatalf("Can't attack chunk %d: %s", i, err)
			}
			//			t.Logf("Got chunk: %s\n", plainChunk)
			plainChunks = append(plainChunks, plainChunk)
			loopIV = c
		}
		s := string(bytes.Join(plainChunks, []byte{}))

		if _, ok := found[s]; !ok {
			//			t.Logf("MSG: %s\n", s)
			loopsWithoutFindingNew = 0
			found[s] = true
		} else {
			loopsWithoutFindingNew++
		}
	}

	var msgs []string
	for k, _ := range found {
		msgs = append(msgs, k)
	}
	sort.Strings(msgs)

	t.Logf("-----------")
	for _, s := range msgs {
		t.Logf("%s\n", s)
	}
}

var C17FixedKey = RandomKey()

func C17PaddingGood(iv, buf []byte) (paddingGood bool) {
	paddingGood = true
	defer func() {
		if r := recover(); r != nil {
			paddingGood = false
		}
	}()
	AESCBCDecrypt(C17FixedKey, iv, buf)
	return
}

func C17Encrypt() ([]byte, []byte) {
	plaintexts := []B64Str{
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
	}
	b64str := plaintexts[rand.Intn(len(plaintexts))]
	msg, err := DeBase64(b64str)
	if err != nil {
		panic("wtf")
	}

	iv := RandomKey()

	buf := AESCBCEncrypt(C17FixedKey, iv, msg)

	return buf, iv
}
