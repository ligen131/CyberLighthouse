package util

const BYTE_OFFSET uint16 = 8

func Byte2ToUint16(a byte, b byte) uint16 {
	return (uint16(a) << BYTE_OFFSET) + uint16(b)
}

func ByteToUint16(data []byte) uint16 {
	if len(data) == 0 {
		return 0
	}
	if len(data) == 1 {
		return uint16(data[0])
	}
	return Byte2ToUint16(data[0], data[1])
}

func ByteToUint32(data []byte) uint32 {
	if len(data) == 0 {
		return 0
	}
	if len(data) == 1 {
		return uint32(data[0])
	}
	if len(data) == 2 {
		return uint32(Byte2ToUint16(data[0], data[1]))
	}
	if len(data) == 3 {
		return (uint32(Byte2ToUint16(data[0], data[1])) << uint32(BYTE_OFFSET)) + uint32(data[2])
	}
	return (uint32(Byte2ToUint16(data[0], data[1])) << uint32(BYTE_OFFSET) << uint32(BYTE_OFFSET)) +
		uint32(Byte2ToUint16(data[2], data[3]))
}
