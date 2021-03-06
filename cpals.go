package cpals // import "github.com/jbert/cpals-go

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"math/rand"
	"net/url"
	"sort"
	"strings"
	"time"

	// We use local SHA1
	"github.com/jbert/cpals-go/md4"
	"github.com/jbert/cpals-go/sha1"
)

var YellowKey = []byte("YELLOW SUBMARINE")
var ZeroIV = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
var Hamlet = []byte(`
To be, or not to be, that is the question:
Whether 'tis nobler in the mind to suffer
The slings and arrows of outrageous fortune,
Or to take arms against a sea of troubles
And by opposing end them. To die-to sleep,
No more; and by a sleep to say we end
The heart-ache and the thousand natural shocks
That flesh is heir to: 'tis a consummation
Devoutly to be wish'd. To die, to sleep;
To sleep, perchance to dream-ay, there's the rub:
For in that sleep of death what dreams may come,
When we have shuffled off this mortal coil,
Must give us pause-there's the respect
That makes calamity of so long life.
For who would bear the whips and scorns of time,
Th'oppressor's wrong, the proud man's contumely,
The pangs of dispriz'd love, the law's delay,
The insolence of office, and the spurns
That patient merit of th'unworthy takes,
When he himself might his quietus make
With a bare bodkin? Who would fardels bear,
To grunt and sweat under a weary life,
But that the dread of something after death,
The undiscovere'd country, from whose bourn
No traveller returns, puzzles the will,
And makes us rather bear those ills we have
Than fly to others that we know not of?
Thus conscience does make cowards of us all,
And thus the native hue of resolution
Is sicklied o'er with the pale cast of thought,
And enterprises of great pitch and moment
With this regard their currents turn awry
And lose the name of action.

-- Will S
`)
var AESBlockSize = len(YellowKey)

func XorKey(msg, key []byte) []byte {
	lenKey := len(key)
	lenMsg := len(msg)
	buf := make([]byte, lenMsg)
	for i := range msg {
		j := i % lenKey
		buf[i] = msg[i] ^ key[j]
	}
	return buf
}

func Xor(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("Can't xor len %d != %d", len(a), len(b))
	}
	ret := make([]byte, len(a))
	for i := range a {
		ret[i] = a[i] ^ b[i]
	}
	return ret, nil
}

func SolveEnglishSingleByteXor(ctxt []byte) ([]byte, float64, byte) {
	var bestB byte
	bestScore := 0.0
	for bi := 0; bi <= 0xff; bi++ {
		b := byte(bi)
		buf := XorByte(ctxt, b)
		score := EnglishScore(buf)
		//fmt.Printf("%02X: %f: %s\n", bi, score, buf)
		if score > bestScore {
			bestB = b
			bestScore = score
		}
	}
	return XorByte(ctxt, bestB), bestScore, bestB
}

func XorByte(buf []byte, b byte) []byte {
	ret := make([]byte, len(buf))
	for i := range buf {
		ret[i] = buf[i] ^ b
	}
	return ret
}

func EnglishScore(msg []byte) float64 {
	score := 0
	boost := map[byte]int{
		'e': 2,
		't': 2,
		'a': 2,
		'o': 2,
		'i': 2,
		'n': 2,

		's': 1,
		'h': 1,
		'r': 1,
		'd': 1,
		'l': 1,
		'u': 1,

		' ': 2,
		// Don't penalise for these
		'.':  0,
		',':  0,
		'\'': 0,
		'"':  0,
	}
	for _, c := range msg {
		if c >= 'A' && c <= 'Z' {
			c = ByteLowerCase(c)
		}
		if c >= 'a' && c <= 'z' {
			score += 1
		}

		extra, ok := boost[c]
		if ok {
			score += extra
		} else {
			score -= 1
		}
	}
	return float64(score) / float64(len(msg))
}

/*
func EnglishScore(msg []byte) float64 {
	chars := []byte(" etaoinshrdlu\n")
	m := make(map[byte]float64)
	for i, b := range chars {
		m[b] = 1 / float64(i+1)
	}

	score := 0.0
	for _, c := range msg {
		if c >= 'A' && c <= 'Z' {
			c = ByteLowerCase(c)
		}
		byteScore, ok := m[c]
		//		fmt.Printf("%c: %f\n", c, byteScore)
		if ok {
			score += byteScore
		} else if c&0x80 > 0 {
			score -= 10.0
		}
	}
	return score / float64(len(msg))
}
*/

func ByteLowerCase(b byte) byte {
	return b | 0x20
}

func HammingDistance(a, b []byte) (int, error) {
	if len(a) != len(b) {
		return 0, fmt.Errorf("Length mismatch %d != %d", len(a), len(b))
	}
	hDist := 0
	for i := range a {
		hDist += byteHammingDist(a[i], b[i])
	}
	return hDist, nil
}

func byteHammingDist(a, b byte) int {
	x := a ^ b
	return bits.OnesCount8(x)
}

func GuessXorKeySize(buf []byte) []int {

	type sizeDistance struct {
		keySize  int
		distance float64
	}
	sizeDistances := make([]sizeDistance, 0)

	for keySize := 2; keySize < 41; keySize++ {
		chunks, _ := BytesToChunks(buf, keySize)

		if len(chunks) < 4 {
			panic("madness")
		}
		distance := 0.0
		chunkDistance, _ := HammingDistance(chunks[0], chunks[1])
		distance += float64(chunkDistance)
		chunkDistance, _ = HammingDistance(chunks[1], chunks[2])
		distance += float64(chunkDistance)
		chunkDistance, _ = HammingDistance(chunks[2], chunks[3])
		distance += float64(chunkDistance)

		distance /= 3.0
		distance /= float64(keySize)

		sizeDistances = append(sizeDistances, sizeDistance{keySize, distance})
	}

	sort.Slice(sizeDistances, func(i, j int) bool {
		return sizeDistances[i].distance < sizeDistances[j].distance
	})

	sortedSizes := make([]int, len(sizeDistances))
	for i := range sizeDistances {
		sortedSizes[i] = sizeDistances[i].keySize
	}
	return sortedSizes
}

func ChunksEqual(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !BytesEqual(a[i], b[i]) {
			return false
		}
	}
	return true
}

func ChunksTranspose(in [][]byte) [][]byte {
	numOut := len(in[0])
	out := make([][]byte, numOut)
	for i := range out {
		out[i] = make([]byte, len(in))
		for j := range out[i] {
			out[i][j] = in[j][i]
		}
	}
	return out
}

type ECBDecrypter struct {
	cipher.Block
}

func NewECBDecrypter(cipher cipher.Block) ECBDecrypter {
	return ECBDecrypter{cipher}
}

// Implent crypto/cipher.BlockMode
func (d *ECBDecrypter) BlockSize() int {
	return d.Block.BlockSize()
}

func (d *ECBDecrypter) CryptBlocks(dst, src []byte) {
	nBlocks := len(src) / d.BlockSize()
	for i := 0; i < nBlocks; i++ {
		d.Decrypt(dst[i*d.BlockSize():], src[i*d.BlockSize():])
	}
}

type ECBEncrypter struct {
	cipher.Block
}

func NewECBEncrypter(cipher cipher.Block) ECBEncrypter {
	return ECBEncrypter{cipher}
}

// Implent crypto/cipher.BlockMode
func (d *ECBEncrypter) BlockSize() int {
	return d.Block.BlockSize()
}

func (d *ECBEncrypter) CryptBlocks(dst, src []byte) {
	nBlocks := len(src) / d.BlockSize()
	for i := 0; i < nBlocks; i++ {
		d.Encrypt(dst[i*d.BlockSize():], src[i*d.BlockSize():])
	}
}

func AESECBDecrypt(key []byte, buf []byte) []byte {
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic(fmt.Sprintf("Can't create aes cipher: %s", err))
	}
	dec := NewECBDecrypter(aes)

	dst := make([]byte, len(buf))
	dec.CryptBlocks(dst, buf)
	dst, err = BytesPKCS7UnPad(dst)
	if err != nil {
		panic(fmt.Sprintf("Can't decrypt - invalid padding: %s", err))
	}
	return dst
}

func AESECBEncrypt(key []byte, buf []byte) []byte {
	buf = BytesPKCS7Pad(buf, AESBlockSize)
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic(fmt.Sprintf("Can't create aes cipher: %s", err))
	}
	dec := NewECBEncrypter(aes)

	dst := make([]byte, len(buf))
	dec.CryptBlocks(dst, buf)
	return dst
}

func BytesFindDuplicateBlock(buf []byte, blockSize int) []byte {
	chunks, _ := BytesToChunks(buf, blockSize)
	m := make(map[string]bool)
	for _, c := range chunks {
		s := string(c)
		_, ok := m[s]
		if ok {
			return c
		}
		m[s] = true
	}
	return nil
}

func BytesPKCS7Pad(buf []byte, blockSize int) []byte {
	padBytes := byte(blockSize - (len(buf) % blockSize))
	padding := make([]byte, padBytes)
	for i := range padding {
		padding[i] = padBytes
	}
	return append(buf, padding...)
}

func BytesPKCS7UnPad(buf []byte) ([]byte, error) {
	if len(buf) == 0 {
		return nil, errors.New("Empty buf is not padded")
	}
	padVal := int(buf[len(buf)-1])
	if padVal > len(buf) {
		return nil, fmt.Errorf("Pad byte too large %d > %d", padVal, len(buf))
	}
	if padVal == 0 {
		return nil, fmt.Errorf("Zero pad byte")
	}
	for i := 0; i < padVal; i++ {
		if buf[len(buf)-1-i] != byte(padVal) {
			return nil, fmt.Errorf("Invalid pad byte %d from end: %d != %d", i, buf[len(buf)-i-1], padVal)
		}
	}
	return buf[:len(buf)-padVal], nil
}

type CBCEncrypter struct {
	cipher.Block
	iv []byte
}

func NewCBCEncrypter(cipher cipher.Block, iv []byte) CBCEncrypter {
	if len(iv) != cipher.BlockSize() {
		panic(fmt.Sprintf("iv length must match blocksize %d != %d", len(iv), cipher.BlockSize()))
	}
	return CBCEncrypter{cipher, iv}
}

func (d *CBCEncrypter) BlockSize() int {
	return d.Block.BlockSize()
}

func (d *CBCEncrypter) CryptBlocks(dst, src []byte) {
	nBlocks := len(src) / d.BlockSize()
	lastCipherBlock := d.iv
	for i := 0; i < nBlocks; i++ {
		srcBlock := src[i*d.BlockSize() : (i+1)*d.BlockSize()]
		srcBlock, err := Xor(srcBlock, lastCipherBlock)
		if err != nil {
			panic(fmt.Sprintf("block size confusion: %s", err))
		}
		d.Encrypt(dst[i*d.BlockSize():], srcBlock)
		lastCipherBlock = dst[i*d.BlockSize() : (i+1)*d.BlockSize()]
	}
}

type CBCDecrypter struct {
	cipher.Block
	iv []byte
}

func NewCBCDecrypter(cipher cipher.Block, iv []byte) CBCDecrypter {
	if len(iv) != cipher.BlockSize() {
		panic(fmt.Sprintf("iv length must match blocksize %d != %d", len(iv), cipher.BlockSize()))
	}
	return CBCDecrypter{cipher, iv}
}

func (d *CBCDecrypter) BlockSize() int {
	return d.Block.BlockSize()
}

func (d *CBCDecrypter) CryptBlocks(dst, src []byte) {
	nBlocks := len(src) / d.BlockSize()
	lastCipherBlock := d.iv
	workBlock := make([]byte, d.BlockSize())
	for i := 0; i < nBlocks; i++ {
		d.Decrypt(workBlock, src[i*d.BlockSize():])
		workBlock, err := Xor(workBlock, lastCipherBlock)
		if err != nil {
			panic(fmt.Sprintf("block size confusion: %s", err))
		}
		copy(dst[i*d.BlockSize():], workBlock)
		lastCipherBlock = src[i*d.BlockSize() : (i+1)*d.BlockSize()]
	}
}

func AESCBCDecrypt(key []byte, iv []byte, buf []byte) []byte {
	return AESCBCDecryptMaybePadding(key, iv, buf, true)
}

func AESCBCDecryptMaybePadding(key []byte, iv []byte, buf []byte, unpad bool) []byte {
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic(fmt.Sprintf("Can't create aes cipher: %s", err))
	}
	dec := NewCBCDecrypter(aes, iv)

	dst := make([]byte, len(buf))
	dec.CryptBlocks(dst, buf)
	if unpad {
		dst, err = BytesPKCS7UnPad(dst)
		if err != nil {
			panic(fmt.Sprintf("Can't decrypt - invalid padding: %s", err))
		}
	}
	return dst
}

func AESCBCEncrypt(key []byte, iv []byte, buf []byte) []byte {
	buf = BytesPKCS7Pad(buf, AESBlockSize)
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic(fmt.Sprintf("Can't create aes cipher: %s", err))
	}
	dec := NewCBCEncrypter(aes, iv)

	dst := make([]byte, len(buf))
	dec.CryptBlocks(dst, buf)
	return dst
}

func RandomRandomBytes(lo, hi int) []byte {
	n := rand.Intn(hi - lo)
	return RandomBytes(n + lo)
}

func RandomBytes(n int) []byte {
	buf := make([]byte, n)
	nRead, err := rand.Read(buf)
	if nRead != n {
		panic(fmt.Sprintf("Only read %d bytes, not %d", nRead, n))
	}
	if err != nil {
		panic(fmt.Sprintf("Error reading random bytes: %s", err))
	}
	return buf
}

func RandomKey() []byte {
	return RandomBytes(len(YellowKey))
}

func FindBlockSizeAndFullPadBlock(blockCryptor func(buf []byte) []byte) (int, []byte) {
	lastLen := 0
	maxBlockSize := 1024
	for i := 0; i < maxBlockSize; i++ {
		in := make([]byte, i)
		buf := blockCryptor(in)
		l := len(buf)
		if l == 0 {
			panic("not a block cipher")
		}
		if lastLen == 0 {
			lastLen = l
			continue
		}
		if lastLen != l {
			blockSize := l - lastLen
			return blockSize, buf[len(buf)-blockSize:]
		}
	}
	panic("Didn't find blocksize")
}

func HasDuplicateBlocks(buf []byte, blockSize int) bool {
	dup := BytesFindDuplicateBlock(buf, blockSize)
	return dup != nil
}

func ParseKeyVal(s string) (map[string]string, error) {
	values, err := url.ParseQuery(s)
	if err != nil {
		return nil, fmt.Errorf("Can't parse as URL: %w", err)
	}
	m := make(map[string]string)
	for k, v := range values {
		//		if len(v) > 1 {
		//			return nil, fmt.Errorf("Multiple values for key %s", k)
		//		}
		m[k] = v[0]
	}
	return m, nil
}

type UserProfile struct {
	email string
	uid   string
	role  string
}

func (up UserProfile) Encode() string {
	return fmt.Sprintf("email=%s&uid=%s&role=%s", up.email, up.uid, up.role)
}

func ProfileFor(email string) string {
	email = strings.ReplaceAll(email, "&=", "")
	up := UserProfile{
		email: email,
		uid:   "10",
		role:  "user",
	}
	return up.Encode()
}

func ParseProfile(s string) (UserProfile, error) {
	var up UserProfile
	m, err := ParseKeyVal(s)
	if err != nil {
		return up, err
	}
	var ok bool
	up.email, ok = m["email"]
	if !ok {
		return up, errors.New("no email")
	}
	up.uid, ok = m["uid"]
	if !ok {
		return up, errors.New("no uid")
	}
	up.role, ok = m["role"]
	if !ok {
		return up, errors.New("no role")
	}
	return up, nil
}

func AESCTRKeyStream(key []byte, nonce int64, bufLen int) []byte {
	ret := make([]byte, bufLen)
	blockCount := int64(0)
	for i := 0; i < bufLen; i += len(key) {
		w := &bytes.Buffer{}
		//		fmt.Printf("i %d blockCount %d\n", i, blockCount)
		binary.Write(w, binary.LittleEndian, nonce)
		binary.Write(w, binary.LittleEndian, blockCount)
		//		fmt.Printf("AES: %s\n", EnHex(w.Bytes()))
		buf := AESECBEncrypt(key, w.Bytes())
		copy(ret[i:], buf) // If ret is short of space, only copies needed
		blockCount++
	}
	return ret
}

func AESCTR(key []byte, nonce int64, in []byte) []byte {
	keystream := AESCTRKeyStream(key, nonce, len(in))
	buf, err := Xor(in, keystream)
	if err != nil {
		panic(fmt.Sprintf("Internal error AESCTR Xor : %s", err))
	}
	return buf
}

func MTKeyStream(seed uint32, bufLen int) []byte {
	mt := NewMT()
	mt.Init(seed)
	ret := make([]byte, bufLen)
	for i := 0; i < bufLen; i += 4 {
		w := &bytes.Buffer{}
		v := mt.ExtractNumber()
		err := binary.Write(w, binary.LittleEndian, v)
		if err != nil {
			panic(fmt.Sprintf("Can't encode number: %s", err))
		}
		copy(ret[i:], w.Bytes()) // If ret is short of space, only copies needed
	}
	return ret
}

func MTStream(seed uint32, in []byte) []byte {
	keystream := MTKeyStream(seed, len(in))
	buf, err := Xor(in, keystream)
	if err != nil {
		panic(fmt.Sprintf("Internal error AESCTR Xor : %s", err))
	}
	return buf
}

func SHA1(in []byte) []byte {
	h := sha1.New()
	h.MustWrite(in)
	return h.Sum(nil)
}

func SHA1PrefixMac(key []byte, msg []byte) []byte {
	// We use local SHA1
	h := sha1.New()
	h.MustWrite(key)
	h.MustWrite(msg)
	return h.Sum(nil)
}

func MD4PrefixMac(key []byte, msg []byte) []byte {
	// We use local SHA1
	h := md4.New()
	h.MustWrite(key)
	h.MustWrite(msg)
	return h.Sum(nil)
}

func InsecureCompare(a, b []byte) bool {
	delay := 1 * time.Millisecond

	for i := range a {
		if i > len(a)-1 {
			return false
		}
		if i > len(b)-1 {
			return false
		}
		if a[i] != b[i] {
			return false
		}
		time.Sleep(delay)
	}
	return true
}
