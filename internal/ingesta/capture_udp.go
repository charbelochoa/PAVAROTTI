package ingesta

import "encoding/binary"

func captureUDP(frame captureFrame) []byte {
	data := captureIPPacket(frame)
	if len(data) == 0 {
		return nil
	}
	switch data[0] >> 4 {
	case 4:
		data = captureIPv4UDP(data)
	case 6:
		data = captureIPv6UDP(data)
	default:
		return nil
	}
	if len(data) < 8 || binary.BigEndian.Uint16(data) != 53 {
		return nil
	}
	length := int(binary.BigEndian.Uint16(data[4:]))
	if length < 8 || length > len(data) {
		return nil
	}
	return data[8:length]
}

func captureIPPacket(frame captureFrame) []byte {
	data := frame.data
	var protocol uint16
	switch frame.link {
	case 1:
		if len(data) < 14 {
			return nil
		}
		protocol, data = binary.BigEndian.Uint16(data[12:]), data[14:]
	case 113:
		if len(data) < 16 {
			return nil
		}
		protocol, data = binary.BigEndian.Uint16(data[14:]), data[16:]
	case 276:
		if len(data) < 20 {
			return nil
		}
		protocol, data = binary.BigEndian.Uint16(data), data[20:]
	case 101, 228, 229:
		return data
	case 0, 108:
		if len(data) < 4 {
			return nil
		}
		return data[4:]
	default:
		return nil
	}
	for protocol == 0x8100 || protocol == 0x88a8 || protocol == 0x9100 {
		if len(data) < 4 {
			return nil
		}
		protocol, data = binary.BigEndian.Uint16(data[2:]), data[4:]
	}
	if len(data) == 0 || (protocol != 0x0800 || data[0]>>4 != 4) && (protocol != 0x86dd || data[0]>>4 != 6) {
		return nil
	}
	return data
}

func captureIPv4UDP(data []byte) []byte {
	if len(data) < 20 || data[9] != 17 || binary.BigEndian.Uint16(data[6:])&0x3fff != 0 {
		return nil
	}
	header := int(data[0]&15) * 4
	length := int(binary.BigEndian.Uint16(data[2:]))
	if header < 20 || length < header || length > len(data) {
		return nil
	}
	return data[header:length]
}

func captureIPv6UDP(data []byte) []byte {
	if len(data) < 40 {
		return nil
	}
	length := int(binary.BigEndian.Uint16(data[4:])) + 40
	if length > len(data) {
		return nil
	}
	protocol := data[6]
	data = data[40:length]
	for extensions := 0; protocol != 17; extensions++ {
		if extensions == 8 || len(data) < 2 {
			return nil
		}
		var size int
		switch protocol {
		case 0, 43, 60:
			size = (int(data[1]) + 1) * 8
		case 44:
			size = 8
			if len(data) < size || binary.BigEndian.Uint16(data[2:]) != 0 {
				return nil
			}
		case 51:
			size = (int(data[1]) + 2) * 4
		default:
			return nil
		}
		if size > len(data) {
			return nil
		}
		protocol, data = data[0], data[size:]
	}
	return data
}
