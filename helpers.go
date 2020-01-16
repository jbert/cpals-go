package cpals

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

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
