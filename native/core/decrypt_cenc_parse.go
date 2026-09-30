package core

import (
	"encoding/binary"
	"errors"
)

// cencSample 描述一个加密样本的文件偏移、大小与 IV 基址（每样本 8 字节 IV，位于 ivBase + index*8）。
type cencSample struct {
	Offset int64
	Length int64
}

type cencIVTable struct {
	Base  int64
	Count int
}

// cencParseResult 解密一条 CENC 轨道所需的全部信息。
type cencParseResult struct {
	KID     [16]byte
	Samples []cencSample
	IV      cencIVTable
}

var errCENCUnsupported = errors.New("CENC 结构不支持")

type cencBoxRef struct {
	start, end, body int64
}

func cencChildren(moov []byte, start, end int64) ([]cencBoxRef, error) {
	var out []cencBoxRef
	position := start
	for position+8 <= end {
		size := int64(binary.BigEndian.Uint32(moov[position : position+4]))
		if size < 8 || position+size > end {
			return nil, errCENCUnsupported
		}
		out = append(out, cencBoxRef{position, position + size, position + 8})
		position += size
	}
	return out, nil
}

// cencParseMoov 解析渐进式 CENC MP4 的加密轨道。
// 约束（与红果实测流一致）：整样本加密、无 subsample、每样本辅助数据为 8 字节 IV。
// 返回样本表（Offset 由 stco+stsc 展开得出，IV 由 ivBase+index*8 读取）。
func cencParseMoov(moov []byte) (*cencParseResult, error) {
	var result cencParseResult
	var sizes []int64
	var chunkOffsets []int64
	type stscEntry struct {
		firstChunk, samplesPerChunk int64
	}
	var stsc []stscEntry
	var ivBase int64
	var ivCount int
	var trackEncrypted bool

	var walk func(start, end int64) error
	walk = func(start, end int64) error {
		children, err := cencChildren(moov, start, end)
		if err != nil {
			return err
		}
		for _, ref := range children {
			boxType := string(moov[ref.start+4 : ref.start+8])
			body := ref.body
			switch boxType {
			case "trak", "mdia", "minf", "stbl", "sinf", "schi":
				if err := walk(ref.body, ref.end); err != nil {
					return err
				}
			case "tenc":
				if ref.end-ref.body < 22 {
					return errCENCUnsupported
				}
				copy(result.KID[:], moov[ref.body+6:ref.body+22])
				trackEncrypted = true
			case "stsz":
				sampleSize := binary.BigEndian.Uint32(moov[body+4 : body+8])
				count := binary.BigEndian.Uint32(moov[body+8 : body+12])
				if sampleSize == 0 {
					if int64(body)+12+int64(count)*4 > ref.end {
						return errCENCUnsupported
					}
					sizes = make([]int64, count)
					for index := int64(0); index < int64(count); index++ {
						sizes[index] = int64(binary.BigEndian.Uint32(moov[body+12+index*4 : body+16+index*4]))
					}
				} else {
					sizes = make([]int64, count)
					for index := range sizes {
						sizes[index] = int64(sampleSize)
					}
				}
			case "stco":
				count := binary.BigEndian.Uint32(moov[body+4 : body+8])
				chunkOffsets = make([]int64, count)
				for index := int64(0); index < int64(count); index++ {
					chunkOffsets[index] = int64(binary.BigEndian.Uint32(moov[body+8+index*4 : body+12+index*4]))
				}
			case "co64":
				count := binary.BigEndian.Uint32(moov[body+4 : body+8])
				chunkOffsets = make([]int64, count)
				for index := int64(0); index < int64(count); index++ {
					chunkOffsets[index] = int64(binary.BigEndian.Uint64(moov[body+8+index*8 : body+16+index*8]))
				}
			case "stsc":
				count := binary.BigEndian.Uint32(moov[body+4 : body+8])
				stsc = stsc[:0]
				for index := int64(0); index < int64(count); index++ {
					base := body + 8 + index*12
					stsc = append(stsc, stscEntry{
						firstChunk:      int64(binary.BigEndian.Uint32(moov[base : base+4])),
						samplesPerChunk: int64(binary.BigEndian.Uint32(moov[base+4 : base+8])),
					})
				}
			case "saio":
				flags := binary.BigEndian.Uint32(moov[body:body+4]) & 0xFFFFFF
				count := binary.BigEndian.Uint32(moov[body+4 : body+8])
				if count != 1 {
					return errCENCUnsupported
				}
				if flags&1 != 0 {
					ivBase = int64(binary.BigEndian.Uint64(moov[body+8 : body+16]))
				} else {
					ivBase = int64(binary.BigEndian.Uint32(moov[body+8 : body+12]))
				}
			case "saiz":
				defaultLen := int(moov[body+4])
				count := binary.BigEndian.Uint32(moov[body+5 : body+9])
				if defaultLen == 0 {
					if int64(body)+9+int64(count) > ref.end {
						return errCENCUnsupported
					}
					for index := int64(0); index < int64(count); index++ {
						if int(moov[body+9+index]) != 8 {
							return errCENCUnsupported
						}
					}
				} else if defaultLen != 8 {
					return errCENCUnsupported
				}
				ivCount = int(count)
			}
		}
		return nil
	}
	if err := walk(0, int64(len(moov))); err != nil {
		return nil, err
	}
	if !trackEncrypted || len(sizes) == 0 || len(chunkOffsets) == 0 || len(stsc) == 0 || ivBase == 0 {
		return nil, errCENCUnsupported
	}
	// stsc 展开样本偏移（chunkOffsets 原地推进为「下一 chunk 的数据起点」）
	samples := make([]cencSample, 0, len(sizes))
	sampleIndex := 0
	for entryIndex, entry := range stsc {
		nextFirst := int64(len(chunkOffsets) + 1)
		if entryIndex+1 < len(stsc) {
			nextFirst = stsc[entryIndex+1].firstChunk
		}
		for chunk := entry.firstChunk; chunk < nextFirst && chunk <= int64(len(chunkOffsets)); chunk++ {
			for inChunk := int64(0); inChunk < entry.samplesPerChunk && sampleIndex < len(sizes); inChunk++ {
				samples = append(samples, cencSample{Offset: chunkOffsets[chunk-1], Length: sizes[sampleIndex]})
				chunkOffsets[chunk-1] += sizes[sampleIndex]
				sampleIndex++
			}
		}
		if sampleIndex >= len(sizes) {
			break
		}
	}
	if sampleIndex != len(sizes) {
		return nil, errCENCUnsupported
	}
	if ivCount != 0 && ivCount != len(samples) {
		return nil, errCENCUnsupported
	}
	result.Samples = samples
	result.IV = cencIVTable{Base: ivBase, Count: len(samples)}
	return &result, nil
}
