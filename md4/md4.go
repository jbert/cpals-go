// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package md4 implements the MD4 hash algorithm as defined in RFC 1320.
//
// Deprecated: MD4 is cryptographically broken and should should only be used
// where compatibility with legacy systems, not security, is the goal. Instead,
// use a secure hash like SHA-256 (from crypto/sha256).
package md4 // import "golang.org/x/crypto/md4"

import (
	"encoding/binary"
	"fmt"
) // The size of an MD4 checksum in bytes.
const Size = 16

// The blocksize of MD4 in bytes.
const BlockSize = 64

const (
	_Chunk = 64
	_Init0 = 0x67452301
	_Init1 = 0xEFCDAB89
	_Init2 = 0x98BADCFE
	_Init3 = 0x10325476
)

// digest represents the partial evaluation of a checksum.
type Digest struct {
	s   [4]uint32
	x   [_Chunk]byte
	nx  int
	len uint64
}

func (d *Digest) Reset() {
	d.s[0] = _Init0
	d.s[1] = _Init1
	d.s[2] = _Init2
	d.s[3] = _Init3
	d.nx = 0
	d.len = 0
}

// New returns a new hash.Hash computing the MD4 checksum.
func New() *Digest {
	d := new(Digest)
	d.Reset()
	return d
}

func CloneFromDigest(msgLen uint64, digest []byte) (*Digest, error) {
	if len(digest) != Size {
		return nil, fmt.Errorf("Wrong size for digest got %d expected %d", len(digest), Size)
	}

	d := New()

	d.s[0] = binary.LittleEndian.Uint32(digest[0:])
	d.s[1] = binary.LittleEndian.Uint32(digest[4:])
	d.s[2] = binary.LittleEndian.Uint32(digest[8:])
	d.s[3] = binary.LittleEndian.Uint32(digest[12:])
	d.len = msgLen + uint64(len(MDPadding(msgLen)))

	return d, nil
}

func (d *Digest) Size() int { return Size }

func (d *Digest) BlockSize() int { return BlockSize }

func (d *Digest) MustWrite(p []byte) {
	n, err := d.Write(p)
	if n != len(p) {
		err = fmt.Errorf("Wrote %d bytes to hash, not %d", n, len(p))
	}
	if err != nil {
		panic(fmt.Sprintf("Can't write to hash: %s", err))
	}
}

func (d *Digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)
	if d.nx > 0 {
		n := len(p)
		if n > _Chunk-d.nx {
			n = _Chunk - d.nx
		}
		for i := 0; i < n; i++ {
			d.x[d.nx+i] = p[i]
		}
		d.nx += n
		if d.nx == _Chunk {
			_Block(d, d.x[0:])
			d.nx = 0
		}
		p = p[n:]
	}
	n := _Block(d, p)
	p = p[n:]
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d0 *Digest) Sum(in []byte) []byte {
	// Make a copy of d0, so that caller can keep writing and summing.
	d := new(Digest)
	*d = *d0

	d.Write(MDPadding(d.len))

	if d.nx != 0 {
		panic("d.nx != 0")
	}

	for _, s := range d.s {
		in = append(in, byte(s>>0))
		in = append(in, byte(s>>8))
		in = append(in, byte(s>>16))
		in = append(in, byte(s>>24))
	}
	return in
}

func MDPadding(len uint64) []byte {
	var padding []byte

	// Padding.  Add a 1 bit and 0 bits until 56 bytes mod 64.
	var tmp [64]byte
	tmp[0] = 0x80

	if len%64 < 56 {
		padding = append(padding, tmp[0:56-len%64]...)
	} else {
		padding = append(padding, tmp[0:64+56-len%64]...)
	}

	// Length in bits.
	len <<= 3
	binary.BigEndian.PutUint64(tmp[:], len)
	padding = append(padding, tmp[0:8]...)

	return padding
}
