package cpals

import "fmt"

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

type PaddingOracle func([]byte) bool

func (po PaddingOracle) AttackBlock(buf []byte) ([]byte, error) {
	blockSize := len(buf)
	attackBlock := make([]byte, blockSize)

POSITION:
	for i := blockSize - 1; i >= 0; i-- {

		// This is the byte we will find for good padding at this position
		paddingByte := blockSize - i

		// Set up the trial block with bit patterns to create the padding we want
		// apart from the current byte
		trialBlock := make([]byte, blockSize)
		copy(trialBlock, attackBlock)
		for j := blockSize - 1; j > i; j-- {
			trialBlock[j] = attackBlock[j] ^ byte(paddingByte)
		}

		// Try each byte in position
		for b := 0; b < 256; b++ {
			trialBlock[i] = byte(b)
			trial := make([]byte, 2*blockSize)
			copy(trial, trialBlock)

			paddingGood := po(trial)
			if paddingGood {
				//				t.Logf("Found %02X for pos %d\n", b, i)
				attackBlock[i] = byte(b) ^ byte(paddingByte)
				continue POSITION
			}
		}
		return nil, fmt.Errorf("Can't find byte for position %d", i)

	}

	return attackBlock, nil
}
