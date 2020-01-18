package cpals

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
)

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
