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

type PaddingOracle func(iv []byte, buf []byte) bool

// AttackBlock calculates what needs to be XORd with the IV to zero
// the cipher block
func (po PaddingOracle) AttackBlock(iv []byte, buf []byte) ([]byte, error) {
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
		trialBlock, err := Xor(trialBlock, iv)
		if err != nil {
			panic("wtf?")
		}

		// Try each byte in position
		for b := 0; b < 256; b++ {
			trialBlock[i] ^= byte(b)

			//			fmt.Printf("TRY: %s\n", BytesHexBlocks(trialBlock, blockSize))
			paddingGood := po(trialBlock, buf)

			if paddingGood {
				// Could be a false positive. If scrambling the next byte is also
				// OK then it isn't
				if i > 0 {
					//					fmt.Printf("Possible %02X for pos %d\n", b, i)
					trialBlock[i-1] ^= 0x01
					paddingGood = po(trialBlock, buf)
					// Remove changes
					trialBlock[i-1] ^= 0x01
				}

				if paddingGood {
					//					fmt.Printf("Found %02X for pos %d\n", b, i)
					attackBlock[i] = byte(b) ^ byte(paddingByte)
					//					fmt.Printf("AB : %s\n", BytesHexBlocks(attackBlock, blockSize))
					trialBlock[i] ^= byte(b)
					continue POSITION
				}
			}
			trialBlock[i] ^= byte(b)
		}
		return nil, fmt.Errorf("Can't find byte for position %d", i)

	}

	return attackBlock, nil
}
