package hmac

import (
	"fmt"
	"hash"
)

type HMAC struct {
	size         int
	blocksize    int
	opad, ipad   []byte
	outer, inner hash.Hash
}

func New(h func() hash.Hash, key []byte) *HMAC {
	hm := new(HMAC)
	hm.outer = h()
	hm.inner = h()
	hm.size = hm.inner.Size()
	hm.blocksize = hm.inner.BlockSize()
	hm.ipad = make([]byte, hm.blocksize)
	hm.opad = make([]byte, hm.blocksize)
	if len(key) > hm.blocksize {
		// If key is too big, hash it.
		hm.outer.Write(key)
		key = hm.outer.Sum(nil)
	}
	copy(hm.ipad, key)
	copy(hm.opad, key)
	for i := range hm.ipad {
		hm.ipad[i] ^= 0x36
	}
	for i := range hm.opad {
		hm.opad[i] ^= 0x5c
	}
	hm.inner.Write(hm.ipad)
	return hm
}

func (h *HMAC) Write(p []byte) (nn int, err error) {
	return h.inner.Write(p)
}

func (h *HMAC) MustWrite(p []byte) {
	n, err := h.Write(p)
	if n != len(p) {
		err = fmt.Errorf("Wrote %d bytes to hash, not %d", n, len(p))
	}
	if err != nil {
		panic(fmt.Sprintf("Can't write to hash: %s", err))
	}
}

func (h *HMAC) Sum(in []byte) []byte {
	origLen := len(in)
	in = h.inner.Sum(in)
	h.outer.Reset()
	h.outer.Write(h.opad)
	h.outer.Write(in[origLen:])
	return h.outer.Sum(in[:origLen])
}

func (h *HMAC) Size() int { return h.size }

func (h *HMAC) BlockSize() int { return h.blocksize }

func (h *HMAC) Reset() {
	h.inner.Reset()
	h.inner.Write(h.ipad)
}
