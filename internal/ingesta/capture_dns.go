package ingesta

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"pavarotti/internal/caso"
)

func parseCaptureDNS(data []byte, name string) ([]caso.Record, error) {
	hash := caso.Hash(data)
	var records []caso.Record
	err := walkCapture(data, func(frame captureFrame) error {
		capture, ok := dnsResponseFromWire(captureUDP(frame))
		if !ok {
			return nil
		}
		items, err := dnsRecords(capture, fmt.Sprintf("pcap/%d", frame.number))
		if err != nil {
			return nil
		}
		if len(records)+len(items) > 5000 {
			return errors.New("la captura admite hasta 5000 registros DNS")
		}
		stamp := frame.stamp.Format(time.RFC3339Nano)
		for _, record := range items {
			record.Kind, record.Time, record.SHA256 = "dns", stamp, hash
			if name != "" {
				record.Details += "\nCaptura · " + name
			}
			records = append(records, record)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, errors.New("la captura no contiene respuestas DNS UDP compatibles")
	}
	return records, nil
}

func dnsResponseFromWire(data []byte) (dnsResponse, bool) {
	if len(data) < 12 || data[2]&0xf8 != 0x80 {
		return dnsResponse{}, false
	}
	count := 0
	for offset := 4; offset < 12; offset += 2 {
		count += int(binary.BigEndian.Uint16(data[offset:]))
	}
	if count > 512 {
		return dnsResponse{}, false
	}
	var message dnsmessage.Message
	if err := message.Unpack(data); err != nil {
		return dnsResponse{}, false
	}
	status := int(message.RCode)
	for _, item := range message.Additionals {
		if item.Header.Type == dnsmessage.TypeOPT {
			status = int(item.Header.ExtendedRCode(message.RCode))
			break
		}
	}
	response := dnsResponse{Status: &status, TC: message.Truncated}
	for index, question := range message.Questions {
		if question.Class == dnsmessage.ClassINET {
			response.Question = append(response.Question, dnsQuestion{Name: question.Name.String(), Type: int(question.Type), ordinal: index + 1})
		}
	}
	for index, answer := range message.Answers {
		if answer.Header.Class != dnsmessage.ClassINET || answer.Header.Type == dnsmessage.TypeOPT {
			continue
		}
		if (answer.Header.Type == dnsmessage.TypeA && answer.Header.Length != 4) ||
			(answer.Header.Type == dnsmessage.TypeAAAA && answer.Header.Length != 16) {
			return dnsResponse{}, false
		}
		value := dnsWireValue(answer.Body)
		if value == "" {
			continue
		}
		ttl := answer.Header.TTL
		question := dnsQuestion{Name: answer.Header.Name.String(), Type: int(answer.Header.Type), ordinal: index + 1}
		response.Answer = append(response.Answer, dnsAnswer{dnsQuestion: question, TTL: &ttl, Data: value})
	}
	return response, true
}

func dnsWireValue(body dnsmessage.ResourceBody) string {
	switch item := body.(type) {
	case *dnsmessage.AResource:
		return netip.AddrFrom4(item.A).String()
	case *dnsmessage.AAAAResource:
		return netip.AddrFrom16(item.AAAA).String()
	case *dnsmessage.NSResource:
		return item.NS.String()
	case *dnsmessage.CNAMEResource:
		return item.CNAME.String()
	case *dnsmessage.PTRResource:
		return item.PTR.String()
	case *dnsmessage.MXResource:
		return fmt.Sprintf("%d %s", item.Pref, item.MX.String())
	case *dnsmessage.SRVResource:
		return fmt.Sprintf("%d %d %d %s", item.Priority, item.Weight, item.Port, item.Target.String())
	case *dnsmessage.SOAResource:
		return fmt.Sprintf("%s %s %d %d %d %d %d", item.NS.String(), item.MBox.String(), item.Serial, item.Refresh, item.Retry, item.Expire, item.MinTTL)
	case *dnsmessage.TXTResource:
		var value strings.Builder
		for index, part := range item.TXT {
			quoted := strconv.Quote(part)
			if value.Len()+1+len(quoted) > 4096 {
				return fmt.Sprintf("TXT de %d fragmentos (valor omitido)", len(item.TXT))
			}
			if index != 0 {
				value.WriteByte(' ')
			}
			value.WriteString(quoted)
		}
		return value.String()
	case *dnsmessage.SVCBResource:
		return dnsServiceValue(item)
	case *dnsmessage.HTTPSResource:
		return dnsServiceValue(&item.SVCBResource)
	case *dnsmessage.UnknownResource:
		if len(item.Data) > 2047 {
			return fmt.Sprintf("RDATA de %d bytes (valor omitido)", len(item.Data))
		}
		return fmt.Sprintf("0x%x", item.Data)
	default:
		return ""
	}
}

func dnsServiceValue(item *dnsmessage.SVCBResource) string {
	base := fmt.Sprintf("%d %s", item.Priority, item.Target.String())
	var value strings.Builder
	value.WriteString(base)
	for _, param := range item.Params {
		if value.Len()+10+2*len(param.Value) > 4096 {
			return fmt.Sprintf("%s (%d parámetros omitidos)", base, len(item.Params))
		}
		fmt.Fprintf(&value, " key%d=%x", param.Key, param.Value)
	}
	return value.String()
}
