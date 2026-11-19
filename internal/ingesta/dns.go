package ingesta

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"pavarotti/internal/caso"
)

type dnsResponse struct {
	Status   *int          `json:"status"`
	TC       bool          `json:"TC"`
	Question []dnsQuestion `json:"question"`
	Answer   []dnsAnswer   `json:"answer"`
}

type dnsQuestion struct {
	Name string `json:"name"`
	Type int    `json:"type"`
}

type dnsAnswer struct {
	dnsQuestion
	TTL  *uint32 `json:"TTL"`
	Data string  `json:"data"`
}

var rrTypes = map[int]string{1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 257: "CAA"}
var dnsStatuses = map[int]string{0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

func parseDNS(data []byte) ([]caso.Record, error) {
	input := bytes.TrimSpace(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}))
	if len(input) == 0 || input[0] != '{' && input[0] != '[' {
		return nil, errors.New("se esperaba una respuesta DNS JSON o un arreglo de respuestas")
	}
	var captures []dnsResponse
	if input[0] == '{' {
		captures = make([]dnsResponse, 1)
		if err := json.Unmarshal(input, &captures[0]); err != nil {
			return nil, fmt.Errorf("respuesta DNS inválida: %w", err)
		}
	} else if err := json.Unmarshal(input, &captures); err != nil {
		return nil, fmt.Errorf("respuestas DNS inválidas: %w", err)
	}
	if len(captures) == 0 || len(captures) > 1000 {
		return nil, errors.New("el archivo debe contener entre 1 y 1000 respuestas DNS")
	}
	hash, stamp := caso.Hash(data), caso.Now()
	records := make([]caso.Record, 0)
	seen := make(map[[3]string]bool)
	add := func(record caso.Record) error {
		key := [3]string{record.Title, record.Source, record.Details}
		if seen[key] {
			return nil
		}
		if len(records) == 5000 {
			return errors.New("la captura admite hasta 5000 registros DNS distintos")
		}
		record.Kind, record.Time, record.SHA256 = "dns", stamp, hash
		seen[key] = true
		records = append(records, record)
		return nil
	}
	for idx, capture := range captures {
		if capture.Status == nil || *capture.Status < 0 || *capture.Status > 4095 ||
			(len(capture.Answer) == 0 && len(capture.Question) == 0) {
			return nil, fmt.Errorf("respuesta %d: faltan el estado, las preguntas o las respuestas DNS", idx+1)
		}
		status := dnsStatuses[*capture.Status]
		if status == "" {
			status = "RCODE " + strconv.Itoa(*capture.Status)
		}
		base := "Estado DNS · " + status
		if capture.TC {
			base += "\nRespuesta truncada"
		}
		for questionIndex, question := range capture.Question {
			name, valid := normalizedDNSName(question.Name)
			if !valid || question.Type < 1 || question.Type > 65535 {
				return nil, fmt.Errorf("respuesta %d, pregunta %d: nombre o tipo DNS inválido", idx+1, questionIndex+1)
			}
			if len(capture.Answer) == 0 || *capture.Status != 0 {
				record := caso.Record{Title: "DNS " + dnsType(question.Type) + " " + name,
					Source: name, Details: base, SourceID: fmt.Sprintf("%d/pregunta/%d", idx+1, questionIndex+1)}
				if err := add(record); err != nil {
					return nil, err
				}
			}
		}
		for answerIndex, answer := range capture.Answer {
			name, valid := normalizedDNSName(answer.Name)
			if !valid || answer.Type < 1 || answer.Type > 65535 {
				return nil, fmt.Errorf("respuesta %d, registro %d: nombre o tipo DNS inválido", idx+1, answerIndex+1)
			}
			value, target, err := dnsData(answer.Type, answer.Data)
			if err != nil {
				return nil, fmt.Errorf("respuesta %d, registro %d: %w", idx+1, answerIndex+1, err)
			}
			details := base + "\nValor · " + value
			if answer.TTL != nil {
				details += fmt.Sprintf("\nTTL · %d s", *answer.TTL)
			}
			source := name
			if target != "" && target != name && target != "." {
				source += ", " + target
			}
			record := caso.Record{Title: dnsType(answer.Type) + " " + name,
				Source: source, Details: details, SourceID: fmt.Sprintf("%d/respuesta/%d", idx+1, answerIndex+1)}
			if err := add(record); err != nil {
				return nil, err
			}
		}
	}
	return records, nil
}

func dnsType(code int) string {
	if known := rrTypes[code]; known != "" {
		return known
	}
	return fmt.Sprintf("TYPE%d", code)
}

func normalizedDNSName(raw string) (string, bool) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "." {
		return raw, true
	}
	name := strings.TrimSuffix(raw, ".")
	if len(name) == 0 || len(name) > 253 {
		return "", false
	}
	for label := range strings.SplitSeq(name, ".") {
		if len(label) < 1 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", false
			}
		}
	}
	return name, true
}

func dnsData(rr int, raw string) (string, string, error) {
	value := strings.TrimSpace(raw)
	if value == "" || len(value) > 4096 || strings.ContainsRune(value, 0) {
		return "", "", errors.New("valor DNS vacío o fuera de rango")
	}
	switch rr {
	case 1, 28:
		address, err := netip.ParseAddr(value)
		if err != nil || address.Zone() != "" || (rr == 1 && !address.Is4()) || (rr == 28 && !address.Is6()) {
			return "", "", errors.New("dirección inválida para el tipo DNS")
		}
		return address.String(), address.String(), nil
	case 2, 5, 12:
		target, valid := normalizedDNSName(value)
		if !valid {
			return "", "", errors.New("destino DNS inválido")
		}
		return target, target, nil
	case 15, 33:
		fields := strings.Fields(value)
		prefix := 1
		if rr == 33 {
			prefix = 3
		}
		if len(fields) != prefix+1 {
			return "", "", errors.New("formato de destino DNS inválido")
		}
		for i := range prefix {
			n, err := strconv.ParseUint(fields[i], 10, 16)
			if err != nil {
				return "", "", errors.New("prioridad, peso o puerto DNS inválido")
			}
			fields[i] = strconv.FormatUint(n, 10)
		}
		target, valid := normalizedDNSName(fields[prefix])
		if !valid {
			return "", "", errors.New("destino DNS inválido")
		}
		fields[prefix] = target
		return strings.Join(fields, " "), target, nil
	}
	return value, "", nil
}
