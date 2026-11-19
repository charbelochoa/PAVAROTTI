package ingesta

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"pavarotti/internal/caso"
)

type stixHeader struct {
	Type        string `json:"type"`
	ID          string `json:"id"`
	SpecVersion string `json:"spec_version"`
}

type stixObject struct {
	stixHeader
	Value          string            `json:"value"`
	Pattern        string            `json:"pattern"`
	PatternType    string            `json:"pattern_type"`
	PatternVersion string            `json:"pattern_version"`
	FirstObserved  string            `json:"first_observed"`
	LastObserved   string            `json:"last_observed"`
	NumberObserved int               `json:"number_observed"`
	ObjectRefs     []string          `json:"object_refs"`
	Relationship   string            `json:"relationship_type"`
	SourceRef      string            `json:"source_ref"`
	TargetRef      string            `json:"target_ref"`
	ResolvesToRefs []string          `json:"resolves_to_refs"`
	BelongsToRefs  []string          `json:"belongs_to_refs"`
	Hashes         map[string]string `json:"hashes"`
	ExternalRefs   []caso.STIXOrigin `json:"external_references"`
}

var stixEquality = regexp.MustCompile(`^\[\s*(domain-name:value|ipv4-addr:value|ipv6-addr:value|file:hashes\.'(?:MD5|SHA-1|SHA-256)')\s*=\s*'([^'\\\r\n]{1,253})'\s*\]$`)

var stixValueType = map[string]string{"domain-name": "dominio", "ipv4-addr": "ipv4", "ipv6-addr": "ipv6"}
var stixFieldType = map[string]string{
	"domain-name:value": "dominio", "ipv4-addr:value": "ipv4", "ipv6-addr:value": "ipv6",
	"file:hashes.'MD5'": "md5", "file:hashes.'SHA-1'": "sha1", "file:hashes.'SHA-256'": "sha256",
}

func parseSTIX(data []byte) ([]caso.Record, error) {
	input := bytes.TrimSpace(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}))
	if !utf8.Valid(input) {
		return nil, errors.New("se esperaba un paquete STIX en UTF-8")
	}
	var bundle struct {
		stixHeader
		Objects []stixObject `json:"objects"`
	}
	if err := json.Unmarshal(input, &bundle); err != nil {
		return nil, fmt.Errorf("paquete STIX inválido: %w", err)
	}
	if bundle.Type != "bundle" || !bundle.valid() || len(bundle.Objects) == 0 || len(bundle.Objects) > caso.MaxSTIXObjects {
		return nil, errors.New("se esperaba un paquete STIX 2.1 con un ID y de 1 a 5000 objetos")
	}
	hash, stamp := caso.Hash(data), caso.Now()
	records := make([]caso.Record, 0, len(bundle.Objects))
	for index, object := range bundle.Objects {
		path := fmt.Sprintf("#/objects/%d", index)
		record, err := object.record(path, hash, stamp)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		records = append(records, record)
	}
	return records, nil
}

func (header stixHeader) valid() bool {
	prefix := header.Type + "--"
	return (header.SpecVersion == "" || header.SpecVersion == "2.1") &&
		len(header.ID) == len(prefix)+36 && strings.HasPrefix(header.ID, prefix) && caso.ValidSTIXID(header.ID)
}

func (object stixObject) record(path, hash, stamp string) (caso.Record, error) {
	if object.Type == "" || object.Type == "bundle" || !object.valid() {
		return caso.Record{}, errors.New("tipo, ID o versión STIX inválidos")
	}
	record := caso.Record{Kind: "stix", Title: "STIX · " + object.Type, SourceID: path,
		Time: stamp, SHA256: hash, Details: "Objeto STIX · " + object.ID, STIX: &caso.STIXObject{ID: object.ID}}
	for _, origin := range object.ExternalRefs {
		if !origin.Valid() ||
			!boundedText(origin.ExternalID, 128) || !boundedText(origin.Description, 512) || len(record.STIX.Origins) == 8 {
			continue
		}
		record.STIX.Origins = append(record.STIX.Origins, origin)
		record.Details += "\nProcedencia declarada · " + origin.ExternalID + " · " + origin.Description
	}
	switch object.Type {
	case "domain-name", "ipv4-addr", "ipv6-addr":
		if len(object.ResolvesToRefs)+len(object.BelongsToRefs) > 256 ||
			!addSTIXRefs(record.STIX, "resuelve a", object.ResolvesToRefs) ||
			!addSTIXRefs(record.STIX, "pertenece a", object.BelongsToRefs) {
			return caso.Record{}, errors.New("referencias de observable STIX inválidas")
		}
		value, valid := stixValue(object.Value, stixValueType[object.Type])
		if !valid {
			prefix, err := netip.ParsePrefix(object.Value)
			if err != nil || prefix.Addr().Is4In6() ||
				!(object.Type == "ipv4-addr" && prefix.Addr().Is4() || object.Type == "ipv6-addr" && prefix.Addr().Is6()) {
				return caso.Record{}, errors.New("valor inválido para el tipo de observable STIX")
			}
			record.Network = prefix.Masked().String()
			record.Title = "Red · " + record.Network
			record.Details += "\nPrefijo declarado · " + prefix.String()
			break
		}
		record.Title = "Observable · " + value.Value
		record.Source = value.Value
	case "file":
		for _, algorithm := range []struct{ name, kind string }{{"SHA-256", "sha256"}, {"SHA-1", "sha1"}, {"MD5", "md5"}} {
			if raw, present := object.Hashes[algorithm.name]; present {
				value, valid := stixValue(raw, algorithm.kind)
				if !valid {
					return caso.Record{}, errors.New("huella de archivo STIX inválida")
				}
				record.FileHashes = append(record.FileHashes, value)
				record.Details += "\n" + algorithm.name + " · " + value.Value
			}
		}
		record.Title = "Archivo STIX"
	case "indicator":
		if object.Pattern == "" || object.PatternType == "" {
			return caso.Record{}, errors.New("faltan el patrón y su tipo en el indicador STIX")
		}
		if item, ok := object.indicator(); ok {
			record.Title = "Indicador · " + item.Value
			record.Indicator = &item
			record.Details += "\nTipo · " + item.Type
		} else {
			record.Details += "\nPatrón fuera del conjunto de igualdades admitidas."
		}
	case "observed-data":
		first, firstErr := time.Parse(time.RFC3339, object.FirstObserved)
		last, lastErr := time.Parse(time.RFC3339, object.LastObserved)
		if firstErr != nil || lastErr != nil || last.Before(first) || object.NumberObserved < 1 ||
			object.NumberObserved > 999999999 || len(object.ObjectRefs) < 1 || len(object.ObjectRefs) > 256 {
			return caso.Record{}, errors.New("periodo, recuento o referencias de observación STIX inválidos")
		}
		if !addSTIXRefs(record.STIX, "observado", object.ObjectRefs) {
			return caso.Record{}, errors.New("referencia de observación STIX inválida")
		}
		record.Title = "Observaciones STIX"
		record.Time = last.UTC().Format(time.RFC3339Nano)
		record.STIX.Observation = &caso.STIXObservation{First: first.UTC().Format(time.RFC3339Nano), Last: record.Time, Count: object.NumberObserved}
		record.Details += fmt.Sprintf("\nPrimera observación · %s\nÚltima observación · %s\nObservaciones · %d\nReferencias\n%s",
			first.UTC().Format(time.RFC3339Nano), record.Time, object.NumberObserved, strings.Join(object.ObjectRefs, "\n"))
	case "note":
		if len(object.ObjectRefs) < 1 || len(object.ObjectRefs) > 256 || !addSTIXRefs(record.STIX, "anotado", object.ObjectRefs) {
			return caso.Record{}, errors.New("referencias de nota STIX inválidas")
		}
		record.Title = "Nota STIX"
	case "relationship":
		if !caso.ValidSTIXID(object.SourceRef) || !caso.ValidSTIXID(object.TargetRef) ||
			strings.TrimSpace(object.Relationship) == "" || !boundedText(object.Relationship, 80) {
			return caso.Record{}, errors.New("tipo o referencias de relación STIX inválidos")
		}
		record.Title = "Relación · " + object.Relationship
		record.Details += "\nOrigen · " + object.SourceRef + "\nDestino · " + object.TargetRef
		record.STIX.Refs = []caso.STIXRef{{Role: "origen", ID: object.SourceRef}, {Role: "destino", ID: object.TargetRef}}
	default:
		record.Details += "\nObjeto conservado por tipo e identificador de origen."
	}
	return record, nil
}

func addSTIXRefs(object *caso.STIXObject, role string, ids []string) bool {
	for _, id := range ids {
		if !caso.ValidSTIXID(id) {
			return false
		}
		object.Refs = append(object.Refs, caso.STIXRef{Role: role, ID: id})
	}
	return true
}

func (object stixObject) indicator() (caso.Indicator, bool) {
	if object.PatternType != "stix" || (object.PatternVersion != "" && object.PatternVersion != "2.1") || len(object.Pattern) > 1024 {
		return caso.Indicator{}, false
	}
	match := stixEquality.FindStringSubmatch(strings.TrimSpace(object.Pattern))
	if match == nil {
		return caso.Indicator{}, false
	}
	return stixValue(match[2], stixFieldType[match[1]])
}

func stixValue(value, kind string) (caso.Indicator, bool) {
	if len(value) > 254 || strings.Contains(value, "[.]") {
		return caso.Indicator{}, false
	}
	if kind == "dominio" {
		if name, ok := caso.NormalizeDNSName(value); ok && name != "." && !strings.Contains(name, "_") {
			if _, err := netip.ParseAddr(name); err != nil {
				return caso.Indicator{Type: kind, Value: name}, true
			}
		}
		return caso.Indicator{}, false
	}
	item, ok := indicator(value)
	if !ok || item.Type != kind {
		return caso.Indicator{}, false
	}
	return item, true
}
