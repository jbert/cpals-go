package cpals

type Oracle func([]byte) []byte

func (oracle Oracle) FindBlockSize() int {
	blockSize, _ := FindBlockSizeAndFullPadBlock(oracle)
	return blockSize
}

func (oracle Oracle) IsECB(blockSize int) bool {
	in := make([]byte, blockSize*16)
	buf := oracle(in)
	return HasDuplicateBlocks(buf, blockSize)
}
