package cpals

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
)

func NewBytes(n int, fill byte) []byte {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = fill
	}
	return buf
}

func BytesToChunks(buf []byte, chunkSize int) ([][]byte, []byte) {
	chunks := make([][]byte, len(buf)/chunkSize)
	for i := 0; i < len(chunks); i++ {
		pos := i * chunkSize
		chunks[i] = buf[pos : pos+chunkSize]
	}
	slop := buf[len(chunks)*chunkSize:]
	return chunks, slop
}

func BytesHexBlocks(buf []byte, blockSize int) string {
	chunks, slop := BytesToChunks(buf, blockSize)
	ss := []string{}
	for _, c := range chunks {
		ss = append(ss, string(EnHex(c)))
	}
	ss = append(ss, string(EnHex(slop)))
	return strings.Join(ss, " ")
}

func BytesEqual(a, b []byte) bool {
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

type HexStr string
type B64Str string

func (h HexStr) Normalise() HexStr {
	allowed := []byte("01234567890abcdefABCDEF")
	m := make(map[byte]struct{})
	for _, b := range allowed {
		m[b] = struct{}{}
	}
	var g []byte
	for _, c := range []byte(h) {
		if _, ok := m[c]; ok {
			g = append(g, c)
		}
	}
	return HexStr(g)
}

func (h HexStr) Equals(g HexStr) bool {
	return h.Normalise() == g.Normalise()
}

func DeHex(in HexStr) ([]byte, error) {
	return hex.DecodeString(string(in))
}

func EnHex(in []byte) HexStr {
	return HexStr(hex.EncodeToString(in))
}

func EnBase64(in []byte) B64Str {
	return B64Str(base64.StdEncoding.EncodeToString(in))
}

func DeBase64(in B64Str) ([]byte, error) {
	return base64.StdEncoding.DecodeString(string(in))
}

func MustLoadB64(fname string) []byte {
	buf, err := LoadB64(fname)
	if err != nil {
		panic(fmt.Sprintf("Couldn't load B64 from %s: %s", fname, err))
	}
	return buf
}

func LoadB64(fname string) ([]byte, error) {
	f, err := os.Open(fname)
	if err != nil {
		return nil, fmt.Errorf("Can't open file [%s]: %w", fname, err)
	}
	defer f.Close()

	return ReadBase64(f)
}

func ReadBase64(r io.Reader) ([]byte, error) {
	dec := base64.NewDecoder(base64.StdEncoding, r)
	return ioutil.ReadAll(dec)
}

func LoadLines(fname string) ([]string, error) {
	f, err := os.Open(fname)
	if err != nil {
		return nil, fmt.Errorf("Can't open file [%s]: %w", fname, err)
	}
	defer f.Close()

	return ReadLines(f)
}

func ReadLines(ior io.Reader) ([]string, error) {
	var lines []string
	br := bufio.NewReader(ior)
LINES:
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break LINES
			}
			return nil, err
		}
		line = strings.TrimRight(line, "\n")
		lines = append(lines, line)
	}
	return lines, nil
}
