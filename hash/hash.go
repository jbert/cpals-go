package hash

import "hash"

type Hash interface {
	hash.Hash
	MustWrite([]byte)
}
