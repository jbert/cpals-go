package cpals

type MT struct {
	x          []uint
	index      uint
	w, n, m, r uint
	a          uint
	u, d       uint
	s, b       uint
	t, c       uint
	l          uint
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

	mt.x = make([]uint, mt.n)
	mt.index = mt.n + 1

	return &mt
}

func (mt *MT) Init(seed uint) {
	f := uint(1812433253)
	mt.index = mt.n

	for ii := range mt.x {
		if ii == 0 {
			mt.x[0] = seed
			continue
		}
		i := uint(ii)
		mt.x[i] = (f*(mt.x[i-1]^(mt.x[i-1]>>(mt.w-2))) + i) & mt.d
	}
}

func (mt *MT) ExtractNumber() uint {
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

func (mt *MT) temper(y uint) uint {
	y = rshiftMask(y, mt.u, mt.d)
	y = lshiftMask(y, mt.s, mt.b)
	y = lshiftMask(y, mt.t, mt.c)
	y = rshiftMask(y, mt.l, 0xFFFFFFFF)
	//	y = y ^ ((y << mt.s) & mt.b)
	//	y = y ^ ((y << mt.t) & mt.c)
	//	y = y ^ (y >> mt.l)
	return y
}

func lshiftMask(y uint, bits uint, mask uint) uint {
	return y ^ ((y << bits) & mask)
}

func rshiftMask(y uint, bits uint, mask uint) uint {
	return y ^ ((y >> bits) & mask)
}

func (mt *MT) twist() {
	lowerMask := uint((1 << mt.r) - 1)
	upperMask := lowerMask ^ 0xffffffff
	for ii := range mt.x {
		i := uint(ii)
		x := (mt.x[i] & upperMask) + (mt.x[(i+1)%mt.n] & lowerMask)
		xA := x >> 1
		if x%2 != 0 {
			xA = xA ^ mt.a
		}
		mt.x[i] = mt.x[(i+mt.m)%mt.n] ^ xA
	}
	mt.index = 0
}
