package cryptopro

import "crypto-pro/internal/domain"

// Minimal definite-length BER reader used by CMS extraction and certificate
// metadata. High-tag-number and indefinite-length encodings are rejected.

func readElement(data []byte, offset, end int) (byte, []byte, error) {
	if offset >= end {
		return 0, nil, domain.Fail(domain.InvalidSignatureStructure)
	}
	tag := data[offset]
	lengthOffset := offset + 1
	if lengthOffset >= end {
		return 0, nil, domain.Fail(domain.InvalidSignatureStructure)
	}
	first := data[lengthOffset]
	if first == 0x80 {
		return 0, nil, domain.Fail(domain.InvalidSignatureStructure)
	}
	var length int
	var valueOffset int
	if first&0x80 == 0 {
		length = int(first)
		valueOffset = lengthOffset + 1
	} else {
		lengthSize := int(first & 0x7f)
		if lengthSize == 0 || lengthSize > 4 || lengthOffset+1+lengthSize > end {
			return 0, nil, domain.Fail(domain.InvalidSignatureStructure)
		}
		for i := 0; i < lengthSize; i++ {
			length = (length << 8) | int(data[lengthOffset+1+i])
		}
		valueOffset = lengthOffset + 1 + lengthSize
	}
	if length < 0 || valueOffset+length > end {
		return 0, nil, domain.Fail(domain.InvalidSignatureStructure)
	}
	return tag, data[valueOffset : valueOffset+length], nil
}

func elementEnd(data []byte, offset int) (int, error) {
	end := len(data)
	if offset >= end {
		return 0, domain.Fail(domain.InvalidSignatureStructure)
	}
	lengthOffset := offset + 1
	if lengthOffset >= end {
		return 0, domain.Fail(domain.InvalidSignatureStructure)
	}
	first := data[lengthOffset]
	if first&0x80 == 0 {
		return lengthOffset + 1 + int(first), nil
	}
	lengthSize := int(first & 0x7f)
	if lengthSize == 0 || lengthSize > 4 || lengthOffset+1+lengthSize > end {
		return 0, domain.Fail(domain.InvalidSignatureStructure)
	}
	length := 0
	for i := 0; i < lengthSize; i++ {
		length = (length << 8) | int(data[lengthOffset+1+i])
	}
	return lengthOffset + 1 + lengthSize + length, nil
}

func readElementAs(data []byte, offset, end int, failure domain.Failure) (byte, []byte, error) {
	tag, value, err := readElement(data, offset, end)
	if err != nil {
		return 0, nil, domain.Fail(failure)
	}
	return tag, value, nil
}

func elementEndAs(data []byte, offset int, failure domain.Failure) (int, error) {
	end, err := elementEnd(data, offset)
	if err != nil {
		return 0, domain.Fail(failure)
	}
	return end, nil
}
