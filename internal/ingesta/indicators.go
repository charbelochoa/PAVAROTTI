package ingesta

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"pavarotti/internal/caso"
)

func parseIndicators(data []byte) ([]caso.Record, error) {
	const maximum = 5000
	lines := bufio.NewScanner(bytes.NewReader(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})))
	lines.Buffer(make([]byte, 1024), 4096)
	seen := make(map[caso.Indicator]struct{})
	records := make([]caso.Record, 0)
	fingerprint, stamp := caso.Hash(data), caso.Now()
	for line := 1; lines.Scan(); line++ {
		value := strings.TrimSpace(lines.Text())
		if value == "" || strings.HasPrefix(value, "#") {
			continue
		}
		item, ok := indicator(value)
		if !ok {
			return nil, fmt.Errorf("indicador inválido en la línea %d", line)
		}
		if _, exists := seen[item]; exists {
			continue
		}
		if len(records) == maximum {
			return nil, errors.New("la lista admite hasta 5000 indicadores distintos")
		}
		seen[item] = struct{}{}
		record := caso.Record{Kind: "indicador", Title: item.Value, Time: stamp, SourceID: fmt.Sprint(line),
			SHA256: fingerprint, Details: "Tipo · " + item.Type, Indicator: &item}
		if item.Type == "dominio" || item.Type == "ipv4" || item.Type == "ipv6" {
			record.Source = item.Value
		}
		records = append(records, record)
	}
	if err := lines.Err(); err != nil {
		return nil, fmt.Errorf("leer lista de indicadores: %w", err)
	}
	if len(records) == 0 {
		return nil, errors.New("la lista no contiene indicadores")
	}
	return records, nil
}

func indicator(raw string) (caso.Indicator, bool) {
	value := strings.ToLower(strings.ReplaceAll(raw, "[.]", "."))
	if address, err := netip.ParseAddr(value); err == nil && address.Zone() == "" {
		address = address.Unmap()
		kind := "ipv6"
		if address.Is4() {
			kind = "ipv4"
		}
		return caso.Indicator{Type: kind, Value: address.String()}, true
	}
	switch len(value) {
	case 32, 40, 64:
		if _, err := hex.DecodeString(value); err == nil {
			return caso.Indicator{Type: map[int]string{32: "md5", 40: "sha1", 64: "sha256"}[len(value)], Value: value}, true
		}
	}
	value = strings.TrimSuffix(value, ".")
	if len(value) > 253 || !strings.Contains(value, ".") {
		return caso.Indicator{}, false
	}
	last := ""
	for label := range strings.SplitSeq(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return caso.Indicator{}, false
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-') {
				return caso.Indicator{}, false
			}
		}
		last = label
	}
	if !strings.ContainsAny(last, "abcdefghijklmnopqrstuvwxyz") {
		return caso.Indicator{}, false
	}
	return caso.Indicator{Type: "dominio", Value: value}, true
}
