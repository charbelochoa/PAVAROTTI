package ingesta

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"pavarotti/internal/caso"
)

type fixtureByteOrder interface {
	binary.ByteOrder
	binary.AppendByteOrder
}

func TestCaptureDNSClassicPreservesPacketEvidence(t *testing.T) {
	reply := dnsCaptureFixture(t, true, false)
	query := dnsCaptureFixture(t, false, false)
	negative := dnsCaptureFixture(t, true, true)
	for _, format := range []struct {
		name  string
		order fixtureByteOrder
		magic uint32
		stamp string
	}{
		{"big microseconds", binary.BigEndian, 0xa1b2c3d4, "2024-01-01T00:00:00.123456Z"},
		{"little microseconds", binary.LittleEndian, 0xa1b2c3d4, "2024-01-01T00:00:00.123456Z"},
		{"big nanoseconds", binary.BigEndian, 0xa1b23c4d, "2024-01-01T00:00:00.000123456Z"},
		{"little nanoseconds", binary.LittleEndian, 0xa1b23c4d, "2024-01-01T00:00:00.000123456Z"},
	} {
		t.Run(format.name, func(t *testing.T) {
			frame := ethernetDNS4(reply)
			fragment := bytes.Clone(frame)
			fragment[18+6] = 0x20
			otherPort := bytes.Clone(frame)
			otherPort[18+21] = 54
			data := classicDNSCapture(format.order, format.magic, ethernetDNS4(query), frame[:len(frame)-1],
				fragment, otherPort, frame, ethernetDNS4(negative), frame)
			records, err := parseCaptureDNS(data, "muestra.pcap")
			if err != nil || len(records) != 5 {
				t.Fatalf("records = %#v, error = %v", records, err)
			}
			ids := []string{"pcap/5/respuesta/1", "pcap/5/respuesta/3", "pcap/6/pregunta/1", "pcap/7/respuesta/1", "pcap/7/respuesta/3"}
			for index, record := range records {
				if record.Kind != "dns" || record.SHA256 != caso.Hash(data) || record.SourceID != ids[index] ||
					!strings.HasSuffix(record.Details, "Captura · muestra.pcap") {
					t.Fatalf("record %d = %#v", index, record)
				}
			}
			if records[0].Time != format.stamp || records[0].Title != "CNAME portal.example.invalid" ||
				records[1].Source != "host.example.invalid, 192.0.2.25" || !strings.Contains(records[1].Details, "TTL · 0 s") ||
				!strings.Contains(records[2].Details, "NXDOMAIN\nRespuesta truncada") || records[4].Time == records[1].Time {
				t.Fatalf("capture values = %#v", records)
			}
			if partial, err := parseCaptureDNS(data[:len(data)-1], ""); !errors.Is(err, errCaptureFormat) || partial != nil {
				t.Fatalf("truncated capture returned %d records, error = %v", len(partial), err)
			}
		})
	}
}

func TestCaptureDNSNextGenerationInterfaces(t *testing.T) {
	wire := dnsCaptureFixture(t, true, false)
	frame6 := ipv6DNSFixture(wire)
	sll2 := append(make([]byte, 20), frame6...)
	binary.BigEndian.PutUint16(sll2, 0x86dd)
	le, be := binary.LittleEndian, binary.BigEndian
	const seconds = 1704067200
	data := bytes.Join([][]byte{
		pcapngDNSSection(le), pcapngDNSInterface(le, 999, 6, 0), pcapngDNSInterface(le, 276, 0x8a, -2),
		pcapngDNSBlock(le, 3, make([]byte, 4)), pcapngDNSPacket(le, 6, 1, (seconds+2)*1024+1, sll2),
		pcapngDNSSection(be), pcapngDNSInterface(be, 101, 9, 0),
		pcapngDNSPacket(be, 2, 0, seconds*1_000_000_000+999_999_999, frame6),
	}, nil)
	records, err := parseCaptureDNS(data, "")
	if err != nil || len(records) != 4 {
		t.Fatalf("records = %#v, error = %v", records, err)
	}
	if records[0].SourceID != "pcap/2/respuesta/1" || records[0].Time != "2024-01-01T00:00:00.000976562Z" ||
		records[2].SourceID != "pcap/3/respuesta/1" || records[2].Time != "2024-01-01T00:00:00.999999999Z" {
		t.Fatalf("capture position and time = %#v", records)
	}
	corrupt := bytes.Clone(data)
	corrupt[len(corrupt)-1] ^= 1
	if records, err := parseCaptureDNS(corrupt, ""); !errors.Is(err, errCaptureFormat) || records != nil {
		t.Fatalf("corrupted block returned %d records, error = %v", len(records), err)
	}
}

func TestCaptureDNSRequiresAnswersAndBoundsRecords(t *testing.T) {
	query := ethernetDNS4(dnsCaptureFixture(t, false, false))
	if records, err := parseCaptureDNS(classicDNSCapture(binary.LittleEndian, 0xa1b2c3d4, query), ""); err == nil || records != nil {
		t.Fatalf("query returned %d records, error = %v", len(records), err)
	}
	frames := make([][]byte, 2501)
	frame := ethernetDNS4(dnsCaptureFixture(t, true, false))
	for index := range frames {
		frames[index] = frame
	}
	if records, err := parseCaptureDNS(classicDNSCapture(binary.LittleEndian, 0xa1b2c3d4, frames...), ""); err == nil || !strings.Contains(err.Error(), "5000") || records != nil {
		t.Fatalf("oversized batch returned %d records, error = %v", len(records), err)
	}
}

func dnsCaptureFixture(t *testing.T, reply, negative bool) []byte {
	t.Helper()
	portal := dnsmessage.MustNewName("portal.example.invalid.")
	host := dnsmessage.MustNewName("host.example.invalid.")
	message := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 7, Response: reply},
		Questions: []dnsmessage.Question{{Name: portal, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	if negative {
		message.Header.Truncated = true
		message.Header.RCode = dnsmessage.RCodeNameError
	} else if reply {
		message.Answers = []dnsmessage.Resource{
			{Header: dnsmessage.ResourceHeader{Name: portal, Class: dnsmessage.ClassINET, TTL: 90}, Body: &dnsmessage.CNAMEResource{CNAME: host}},
			{Header: dnsmessage.ResourceHeader{Name: host, Class: dnsmessage.ClassCHAOS, TTL: 22}, Body: &dnsmessage.TXTResource{TXT: []string{"chaos"}}},
			{Header: dnsmessage.ResourceHeader{Name: host, Class: dnsmessage.ClassINET}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 25}}},
		}
	}
	data, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func classicDNSCapture(order fixtureByteOrder, magic uint32, frames ...[]byte) []byte {
	data := make([]byte, 24)
	order.PutUint32(data, magic)
	order.PutUint16(data[4:], 2)
	order.PutUint16(data[6:], 4)
	order.PutUint32(data[16:], 65535)
	order.PutUint32(data[20:], 1)
	for index, frame := range frames {
		data = order.AppendUint32(data, 1704067200+uint32(max(0, index-4)))
		data = order.AppendUint32(data, 123456)
		data = order.AppendUint32(data, uint32(len(frame)))
		data = order.AppendUint32(data, uint32(len(frame)))
		data = append(data, frame...)
	}
	return data
}

func ethernetDNS4(payload []byte) []byte {
	frame := make([]byte, 18+20+8)
	binary.BigEndian.PutUint16(frame[12:], 0x8100)
	binary.BigEndian.PutUint16(frame[16:], 0x0800)
	ip := frame[18:]
	ip[0], ip[9] = 0x45, 17
	binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)+len(payload)))
	writeDNSFixtureUDP(ip[20:], payload)
	return append(frame, payload...)
}

func ipv6DNSFixture(payload []byte) []byte {
	frame := make([]byte, 40+8+8)
	frame[0], frame[6], frame[40] = 0x60, 60, 17
	binary.BigEndian.PutUint16(frame[4:], uint16(len(frame)-40+len(payload)))
	writeDNSFixtureUDP(frame[48:], payload)
	return append(frame, payload...)
}

func writeDNSFixtureUDP(udp, payload []byte) {
	binary.BigEndian.PutUint16(udp, 53)
	binary.BigEndian.PutUint16(udp[2:], 12345)
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)+len(payload)))
}

func pcapngDNSBlock(order fixtureByteOrder, kind uint32, body []byte) []byte {
	length := uint32(len(body) + 12)
	data := order.AppendUint32(nil, kind)
	data = order.AppendUint32(data, length)
	data = append(data, body...)
	return order.AppendUint32(data, length)
}

func pcapngDNSSection(order fixtureByteOrder) []byte {
	body := order.AppendUint32(nil, 0x1a2b3c4d)
	body = order.AppendUint16(body, 1)
	body = order.AppendUint16(body, 0)
	body = order.AppendUint64(body, ^uint64(0))
	return pcapngDNSBlock(order, 0x0a0d0d0a, body)
}

func pcapngDNSInterface(order fixtureByteOrder, link uint16, resolution byte, offset int64) []byte {
	body := order.AppendUint16(nil, link)
	body = order.AppendUint16(body, 0)
	body = order.AppendUint32(body, 65535)
	body = order.AppendUint16(body, 9)
	body = order.AppendUint16(body, 1)
	body = append(body, resolution, 0, 0, 0)
	body = order.AppendUint16(body, 14)
	body = order.AppendUint16(body, 8)
	body = order.AppendUint64(body, uint64(offset))
	body = order.AppendUint32(body, 0)
	return pcapngDNSBlock(order, 1, body)
}

func pcapngDNSPacket(order fixtureByteOrder, kind, iface uint32, ticks uint64, frame []byte) []byte {
	body := order.AppendUint32(nil, iface)
	if kind == 2 {
		body = order.AppendUint16(nil, uint16(iface))
		body = order.AppendUint16(body, 0)
	}
	body = order.AppendUint32(body, uint32(ticks>>32))
	body = order.AppendUint32(body, uint32(ticks))
	body = order.AppendUint32(body, uint32(len(frame)))
	body = order.AppendUint32(body, uint32(len(frame)))
	body = append(body, frame...)
	body = append(body, make([]byte, (4-len(frame)%4)%4)...)
	return pcapngDNSBlock(order, kind, body)
}
