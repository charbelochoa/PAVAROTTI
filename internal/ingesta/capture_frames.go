package ingesta

import (
	"encoding/binary"
	"errors"
	"math"
	"math/bits"
	"time"
)

var errCaptureFormat = errors.New("la estructura del archivo PCAP o PCAPNG no es válida")

type captureFrame struct {
	number int
	link   uint32
	stamp  time.Time
	data   []byte
}

func walkCapture(data []byte, visit func(captureFrame) error) error {
	if len(data) < 4 {
		return errCaptureFormat
	}
	switch binary.BigEndian.Uint32(data) {
	case 0xa1b2c3d4:
		return walkPCAP(data, binary.BigEndian, 1_000_000, visit)
	case 0xd4c3b2a1:
		return walkPCAP(data, binary.LittleEndian, 1_000_000, visit)
	case 0xa1b23c4d:
		return walkPCAP(data, binary.BigEndian, 1_000_000_000, visit)
	case 0x4d3cb2a1:
		return walkPCAP(data, binary.LittleEndian, 1_000_000_000, visit)
	case 0x0a0d0d0a:
		return walkPCAPNG(data, visit)
	default:
		return errCaptureFormat
	}
}

func walkPCAP(data []byte, order binary.ByteOrder, resolution uint32, visit func(captureFrame) error) error {
	if len(data) < 24 || order.Uint16(data[4:]) != 2 || order.Uint16(data[6:]) != 4 {
		return errCaptureFormat
	}
	snaplen, link := order.Uint32(data[16:]), order.Uint32(data[20:])&0xffff
	if snaplen == 0 {
		return errCaptureFormat
	}
	data = data[24:]
	for number := 1; len(data) != 0; number++ {
		if len(data) < 16 {
			return errCaptureFormat
		}
		seconds, fraction := order.Uint32(data), order.Uint32(data[4:])
		captured, original := order.Uint32(data[8:]), order.Uint32(data[12:])
		data = data[16:]
		if fraction >= resolution || captured > snaplen || captured > original || uint64(captured) > uint64(len(data)) {
			return errCaptureFormat
		}
		stamp := time.Unix(int64(seconds), int64(fraction)*(1_000_000_000/int64(resolution))).UTC()
		if err := visit(captureFrame{number, link, stamp, data[:captured]}); err != nil {
			return err
		}
		data = data[captured:]
	}
	return nil
}

type captureInterface struct {
	link, snaplen uint32
	resolution    uint64
	offset        int64
}

func walkPCAPNG(data []byte, visit func(captureFrame) error) error {
	const section = 0x0a0d0d0a
	var order binary.ByteOrder
	var interfaces []captureInterface
	number := 0
	for len(data) != 0 {
		if len(data) < 12 {
			return errCaptureFormat
		}
		if binary.BigEndian.Uint32(data) == section {
			switch binary.BigEndian.Uint32(data[8:]) {
			case 0x1a2b3c4d:
				order = binary.BigEndian
			case 0x4d3c2b1a:
				order = binary.LittleEndian
			default:
				return errCaptureFormat
			}
		}
		if order == nil {
			return errCaptureFormat
		}
		kind, length := order.Uint32(data), order.Uint32(data[4:])
		if length < 12 || length%4 != 0 || uint64(length) > uint64(len(data)) || order.Uint32(data[length-4:]) != length {
			return errCaptureFormat
		}
		body := data[8 : length-4]
		data = data[length:]
		switch kind {
		case section:
			if len(body) < 16 || order.Uint16(body[4:]) != 1 {
				return errCaptureFormat
			}
			interfaces = interfaces[:0]
		case 1:
			if len(interfaces) == 1024 {
				return errCaptureFormat
			}
			iface, err := parseCaptureInterface(body, order)
			if err != nil {
				return err
			}
			interfaces = append(interfaces, iface)
		case 2, 6:
			number++
			frame, err := parseCapturePacket(body, interfaces, order, kind == 2, number)
			if err != nil {
				return err
			}
			if err := visit(frame); err != nil {
				return err
			}
		case 3:
			if len(body) < 4 || len(interfaces) == 0 {
				return errCaptureFormat
			}
			captured := order.Uint32(body)
			if interfaces[0].snaplen != 0 {
				captured = min(captured, interfaces[0].snaplen)
			}
			if (uint64(captured)+3)&^3 != uint64(len(body)-4) {
				return errCaptureFormat
			}
			number++
		}
	}
	return nil
}

func parseCaptureInterface(body []byte, order binary.ByteOrder) (captureInterface, error) {
	if len(body) < 8 {
		return captureInterface{}, errCaptureFormat
	}
	iface := captureInterface{link: uint32(order.Uint16(body)), snaplen: order.Uint32(body[4:]), resolution: 1_000_000}
	for options := body[8:]; len(options) != 0; {
		if len(options) < 4 {
			return captureInterface{}, errCaptureFormat
		}
		kind, length := order.Uint16(options), int(order.Uint16(options[2:]))
		padded := (length + 3) &^ 3
		options = options[4:]
		if padded > len(options) || (kind == 0 && (length != 0 || len(options) != 0)) {
			return captureInterface{}, errCaptureFormat
		}
		switch kind {
		case 9:
			if length != 1 {
				return captureInterface{}, errCaptureFormat
			}
			exponent := options[0]
			if exponent&0x80 != 0 {
				if exponent&0x7f >= 64 {
					return captureInterface{}, errCaptureFormat
				}
				iface.resolution = 1 << (exponent & 0x7f)
			} else {
				if exponent > 19 {
					return captureInterface{}, errCaptureFormat
				}
				iface.resolution = 1
				for range exponent {
					iface.resolution *= 10
				}
			}
		case 14:
			if length != 8 {
				return captureInterface{}, errCaptureFormat
			}
			iface.offset = int64(order.Uint64(options))
		}
		options = options[padded:]
	}
	return iface, nil
}

func parseCapturePacket(body []byte, interfaces []captureInterface, order binary.ByteOrder, old bool, number int) (captureFrame, error) {
	if len(body) < 20 {
		return captureFrame{}, errCaptureFormat
	}
	index := order.Uint32(body)
	if old {
		index = uint32(order.Uint16(body))
	}
	if uint64(index) >= uint64(len(interfaces)) {
		return captureFrame{}, errCaptureFormat
	}
	iface := interfaces[index]
	captured, original := order.Uint32(body[12:]), order.Uint32(body[16:])
	padded := (uint64(captured) + 3) &^ 3
	if captured > original || (iface.snaplen != 0 && captured > iface.snaplen) || padded > uint64(len(body)-20) {
		return captureFrame{}, errCaptureFormat
	}
	ticks := uint64(order.Uint32(body[4:]))<<32 | uint64(order.Uint32(body[8:]))
	seconds := ticks / iface.resolution
	if seconds > math.MaxInt64 || (iface.offset > 0 && seconds > uint64(math.MaxInt64-iface.offset)) {
		return captureFrame{}, errCaptureFormat
	}
	hi, lo := bits.Mul64(ticks%iface.resolution, 1_000_000_000)
	nanos, _ := bits.Div64(hi, lo, iface.resolution)
	unixSeconds := int64(seconds) + iface.offset
	if unixSeconds < -62135596800 || unixSeconds > 253402300799 {
		return captureFrame{}, errCaptureFormat
	}
	stamp := time.Unix(unixSeconds, int64(nanos)).UTC()
	return captureFrame{number, iface.link, stamp, body[20 : 20+captured]}, nil
}
