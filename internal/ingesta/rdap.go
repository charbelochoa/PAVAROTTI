package ingesta

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"pavarotti/internal/caso"
)

type rdapObject struct {
	Class       string           `json:"objectClassName"`
	Handle      string           `json:"handle"`
	LDHName     string           `json:"ldhName"`
	Name        string           `json:"name"`
	Country     string           `json:"country"`
	IPVersion   string           `json:"ipVersion"`
	Start       string           `json:"startAddress"`
	End         string           `json:"endAddress"`
	Nameservers []rdapNameserver `json:"nameservers"`
	Status      []string         `json:"status"`
	Events      []rdapEvent      `json:"events"`
}

type rdapNameserver struct {
	LDHName string `json:"ldhName"`
}

type rdapEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

func parseRDAP(data []byte) ([]caso.Record, error) {
	input := bytes.TrimSpace(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}))
	if len(input) == 0 || input[0] != '{' || !utf8.Valid(input) {
		return nil, errors.New("se esperaba una respuesta RDAP JSON en UTF-8")
	}
	var response struct {
		rdapObject
		Domains *[]rdapObject `json:"domainSearchResults"`
	}
	if err := json.Unmarshal(input, &response); err != nil {
		return nil, fmt.Errorf("respuesta RDAP inválida: %w", err)
	}
	if response.Domains == nil {
		record, err := response.rdapObject.record("#", caso.Hash(data), caso.Now())
		if err != nil {
			return nil, err
		}
		return []caso.Record{record}, nil
	}
	objects := *response.Domains
	if response.Class != "" || len(objects) == 0 || len(objects) > 1000 {
		return nil, errors.New("se esperaban entre 1 y 1000 resultados en la búsqueda RDAP")
	}
	hash, stamp := caso.Hash(data), caso.Now()
	records := make([]caso.Record, 0, len(objects))
	for index, object := range objects {
		path := fmt.Sprintf("#/domainSearchResults/%d", index)
		if object.Class != "domain" {
			return nil, fmt.Errorf("%s: se esperaba un objeto de dominio RDAP", path)
		}
		record, err := object.record(path, hash, stamp)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		records = append(records, record)
	}
	return records, nil
}

func (object rdapObject) record(path, hash, stamp string) (caso.Record, error) {
	var title string
	var sources, details []string
	if len(object.Nameservers) > 31 || len(object.Status) > 32 || len(object.Events) > 64 ||
		!validRDAPText(object.Handle, 253) {
		return caso.Record{}, errors.New("los metadatos RDAP exceden los límites de importación")
	}
	switch object.Class {
	case "domain":
		name, ok := normalizedDNSName(object.LDHName)
		if !ok || name == "." || strings.Contains(name, "_") {
			return caso.Record{}, errors.New("ldhName RDAP inválido")
		}
		title = "Dominio · " + name
		sources = append(sources, name)
		for _, server := range object.Nameservers {
			name, ok := normalizedDNSName(server.LDHName)
			if !ok || name == "." || strings.Contains(name, "_") {
				return caso.Record{}, errors.New("nombre de servidor RDAP inválido")
			}
			sources = append(sources, name)
			details = append(details, "Servidor de nombre · "+name)
		}
	case "ip network":
		start, startErr := netip.ParseAddr(object.Start)
		end, endErr := netip.ParseAddr(object.End)
		if startErr != nil || endErr != nil || start.Zone() != "" || end.Zone() != "" || start.Is4In6() || end.Is4In6() ||
			start.BitLen() != end.BitLen() || start.Compare(end) > 0 ||
			!(object.IPVersion == "v4" && start.Is4() || object.IPVersion == "v6" && start.Is6()) {
			return caso.Record{}, errors.New("rango o versión IP RDAP inválidos")
		}
		title = "Red · " + start.String() + " – " + end.String()
		if !validRDAPText(object.Name, 253) || !validRDAPText(object.Country, 2) {
			return caso.Record{}, errors.New("nombre o país de red RDAP inválido")
		}
		if object.Name != "" {
			details = append(details, "Nombre de la red · "+object.Name)
		}
		if object.Country != "" {
			details = append(details, "País registrado · "+object.Country)
		}
		if start == end {
			sources = append(sources, start.String())
		}
	default:
		return caso.Record{}, errors.New("RDAP admite objetos de dominio y rangos IP")
	}
	if object.Handle != "" {
		details = append(details, "Identificador RDAP · "+object.Handle)
	}
	for _, status := range object.Status {
		if strings.TrimSpace(status) == "" || !validRDAPText(status, 80) {
			return caso.Record{}, errors.New("estado RDAP inválido")
		}
		details = append(details, "Estado · "+status)
	}
	for _, event := range object.Events {
		date, err := time.Parse(time.RFC3339, event.Date)
		if err != nil || strings.TrimSpace(event.Action) == "" || !validRDAPText(event.Action, 80) {
			return caso.Record{}, errors.New("evento o fecha RDAP inválidos")
		}
		details = append(details, event.Action+" · "+date.UTC().Format(time.RFC3339Nano))
	}
	return caso.Record{Kind: "rdap", Time: stamp, Title: title, Source: strings.Join(sources, ", "),
		SourceID: path, SHA256: hash, Details: strings.Join(details, "\n")}, nil
}

func validRDAPText(value string, maximum int) bool {
	return len(value) <= maximum && strings.IndexFunc(value, unicode.IsControl) == -1 &&
		strings.IndexFunc(value, func(char rune) bool { return unicode.In(char, unicode.Cf) }) == -1
}
