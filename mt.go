package cpals

type MT struct {
	x          []uint32
	index      uint32
	w, n, m, r uint32
	a          uint32
	u, d       uint32
	s, b       uint32
	t, c       uint32
	l          uint32
}

func NewMT() *MT {
	mt := MT{}

	mt.w = 32
	mt.n = 624
	mt.m = 397
	mt.r = 31

	mt.a = 0x9908B0DF

	mt.u = 11
	mt.d = 0xFFFFFFFF

	mt.s = 7
	mt.b = 0x9D2C5680

	mt.t = 15
	mt.c = 0xEFC60000

	mt.l = 18

	mt.x = make([]uint32, mt.n)
	mt.index = mt.n + 1

	return &mt
}

func (mt *MT) Init(seed uint32) {
	f := uint32(1812433253)
	mt.index = mt.n

	for ii := range mt.x {
		if ii == 0 {
			mt.x[0] = seed
			continue
		}
		i := uint32(ii)
		mt.x[i] = (f*(mt.x[i-1]^(mt.x[i-1]>>(mt.w-2))) + i) & mt.d
	}
}

func (mt *MT) ExtractNumber() uint32 {
	if mt.index >= mt.n {
		if mt.index > mt.n {
			panic("Generator not seeded")
		}
		mt.twist()
	}

	//    def temper(self, y):
	//        y = self.rshift(y, self.u, self.d)
	//        y = self.lshift(y, self.s, self.b)
	//        y = self.lshift(y, self.t, self.c)
	//        y = self.rshift(y, self.L, 0xffffffff)

	y := mt.temper(mt.x[mt.index])
	mt.index++
	return y
}

func (mt *MT) temper(y uint32) uint32 {
	y = rshiftMask(y, mt.u, mt.d)
	y = lshiftMask(y, mt.s, mt.b)
	y = lshiftMask(y, mt.t, mt.c)
	y = rshiftMask(y, mt.l, 0xFFFFFFFF)
	return y
}

func lshiftMask(y, bits, mask uint32) uint32 {
	return y ^ ((y << bits) & mask)
}

func rshiftMask(y, bits, mask uint32) uint32 {
	return y ^ ((y >> bits) & mask)
}

func (mt *MT) CloneFromObservations(obs []uint32) *MT {
	clone := NewMT()
	clone.Init(0)
	for i := range obs {
		clone.x[i] = mt.untemper(obs[i])
	}
	return clone
}

func (mt *MT) untemper(y uint32) uint32 {
	y = invertRshiftMask(y, mt.l, 0xFFFFFFFF)
	y = invertLshiftMask(y, mt.t, mt.c)
	y = invertLshiftMask(y, mt.s, mt.b)
	y = invertRshiftMask(y, mt.u, mt.d)
	return y
}

func invertRshiftMask(y, bits, mask uint32) uint32 {
	readMask := uint32(1 << 31)
	writeMask := uint32(readMask >> bits)
	for writeMask > 0 {
		bit := y & readMask
		if bit != 0 {
			y = y ^ writeMask&mask
		}

		readMask = readMask >> 1
		writeMask = writeMask >> 1
	}
	return y
}

func invertLshiftMask(y, bits, mask uint32) uint32 {
	readMask := uint32(1)
	writeMask := uint32(readMask << bits)
	for writeMask > 0 {
		bit := y & readMask
		if bit != 0 {
			y = y ^ writeMask&mask
		}

		readMask = readMask << 1
		writeMask = writeMask << 1
		writeMask &= 0xffffffff
	}
	return y
}

func (mt *MT) twist() {
	lowerMask := uint32((1 << mt.r) - 1)
	upperMask := lowerMask ^ 0xffffffff
	for ii := range mt.x {
		i := uint32(ii)
		x := (mt.x[i] & upperMask) + (mt.x[(i+1)%mt.n] & lowerMask)
		xA := x >> 1
		if x%2 != 0 {
			xA = xA ^ mt.a
		}
		mt.x[i] = mt.x[(i+mt.m)%mt.n] ^ xA
	}
	mt.index = 0
}
