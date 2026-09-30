package core

import (
	"crypto/aes"
	"encoding/binary"
	"sort"
)

// cencTrack 持有一条加密轨道的解密上下文。
// IVBytes 为每样本 8 字节 IV 的连续表（来自 moov 的 saio 指向区，moov 下载时一并缓存）。
type cencTrack struct {
	Key     [16]byte
	Samples []cencSample
	IVBytes []byte
}

// decryptRange 解密 buffer（密文，对应文件绝对偏移 start 起的字节区间），原长度返回明文。
// 样本间隙（stco 展开后未覆盖的字节，如 free 盒）按原样保留。
func (track *cencTrack) decryptRange(buffer []byte, start int64) ([]byte, error) {
	block, err := aes.NewCipher(track.Key[:])
	if err != nil {
		return nil, err
	}
	output := make([]byte, len(buffer))
	copy(output, buffer)
	index := sort.Search(len(track.Samples), func(i int) bool {
		return track.Samples[i].Offset+track.Samples[i].Length > start
	})
	cursor := start
	for ; index < len(track.Samples); index++ {
		sample := track.Samples[index]
		sampleEnd := sample.Offset + sample.Length
		if sampleEnd <= cursor {
			continue
		}
		from := sample.Offset
		if from < cursor {
			from = cursor
		}
		to := sampleEnd
		if limit := start + int64(len(buffer)); to > limit {
			to = limit
		}
		if to <= from {
			continue
		}
		if int(index*8+8) > len(track.IVBytes) {
			break
		}
		var counter [16]byte
		copy(counter[0:8], track.IVBytes[index*8:(index+1)*8])
		binary.BigEndian.PutUint64(counter[8:16], 1)
		// 样本内 CTR：计数器按 16 字节块递增；先对齐到目标块
		inOffset := from - sample.Offset
		blockIndex := inOffset / aes.BlockSize
		skipBlocks(block, &counter, blockIndex)
		offsetInBlock := int(inOffset % aes.BlockSize)
		if offsetInBlock > 0 {
			ks := make([]byte, aes.BlockSize)
			block.Encrypt(ks, counter[:])
			chunk := output[int(from-start):int(to-start)]
			for position := offsetInBlock; position < aes.BlockSize && int64(position-offsetInBlock) < to-from; position++ {
				chunk[position-offsetInBlock] ^= ks[position]
			}
			binary.BigEndian.PutUint64(counter[8:16], uint64(blockIndex)+2)
			from += int64(aes.BlockSize - offsetInBlock)
		}
		chunk := output[int(from-start):int(to-start)]
		ks := make([]byte, aes.BlockSize)
		for position := 0; position+aes.BlockSize <= len(chunk); position += aes.BlockSize {
			block.Encrypt(ks, counter[:])
			for b := 0; b < aes.BlockSize; b++ {
				chunk[position+b] ^= ks[b]
			}
			binary.BigEndian.PutUint64(counter[8:16], binary.BigEndian.Uint64(counter[8:16])+1)
		}
		rest := len(chunk) % aes.BlockSize
		if rest > 0 {
			ks := make([]byte, aes.BlockSize)
			block.Encrypt(ks, counter[:])
			for b := 0; b < rest; b++ {
				chunk[len(chunk)-rest+b] ^= ks[b]
			}
		}
		cursor = to
		if cursor >= start+int64(len(buffer)) {
			break
		}
	}
	return output, nil
}

func skipBlocks(block cipherBlock, counter *[16]byte, blocks int64) {
	binary.BigEndian.PutUint64(counter[8:16], binary.BigEndian.Uint64(counter[8:16])+uint64(blocks))
}

type cipherBlock interface {
	Encrypt(dst, src []byte)
}
