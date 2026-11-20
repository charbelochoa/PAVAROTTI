package ingesta

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"pavarotti/internal/caso"
	"pavarotti/internal/revision"
	"pavarotti/internal/trafico"
	"pavarotti/internal/triaje"
)

const MaxBytes = 32 << 20

var (
	ErrKind = errors.New("tipo de archivo desconocido, usa har, hallazgos, binario, codigo, gomod, npmlock, indicadores, dns, pcap-dns, rdap o stix")
	ErrSize = errors.New("el archivo supera el límite")
)

func Parse(kind string, reader io.Reader) ([]caso.Record, error) {
	return ParseNamed(kind, reader, "")
}

func ParseNamed(kind string, reader io.Reader, name string) ([]caso.Record, error) {
	limit := MaxBytes
	switch kind {
	case "har", "hallazgos", "indicadores", "dns", "pcap-dns", "rdap", "stix":
	case "binario":
		limit = triaje.MaxBinaryBytes
	case "codigo":
		limit = revision.MaxSource
	case "gomod", "npmlock":
		limit = revision.MaxManifest
	default:
		return nil, ErrKind
	}

	data, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("leer archivo: %w", err)
	}
	if len(data) > limit {
		return nil, fmt.Errorf("%w de %d MiB", ErrSize, limit>>20)
	}
	if len(data) == 0 {
		return nil, errors.New("el archivo está vacío")
	}

	switch kind {
	case "har":
		return trafico.ImportHAR(data)
	case "hallazgos":
		return caso.Findings(data)
	case "indicadores":
		return parseIndicators(data)
	case "dns":
		return parseDNS(data)
	case "pcap-dns":
		return parseCaptureDNS(data, sourceName(name))
	case "rdap":
		return parseRDAP(data)
	case "stix":
		return parseSTIX(data)
	case "codigo":
		report, err := revision.ReviewGo(data)
		if err != nil {
			return nil, err
		}
		details, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return nil, err
		}
		signals := make([]string, 0, len(report.Signals))
		for _, signal := range report.Signals {
			signals = append(signals, fmt.Sprintf("Línea %d · %s", signal.Line, signal.Review))
		}
		return []caso.Record{{Kind: "código", Time: caso.Now(), Title: "Revisión Go · " + report.Package,
			SHA256: caso.Hash(data), SourceID: sourceName(name), Details: string(details), Signals: signals, Review: &report}}, nil
	case "gomod", "npmlock":
		inventory, err := revision.Inventory(kind, data)
		if err != nil {
			return nil, err
		}
		label := sourceName(name)
		if label == "" {
			label = inventory.Manifest
		}
		title := "Dependencias · " + inventory.Manifest
		if inventory.Project != "" {
			title += " · " + inventory.Project
		}
		return []caso.Record{{Kind: "dependencias", Time: caso.Now(), Title: title, SourceID: label,
			SHA256: caso.Hash(data), Dependencies: &inventory}}, nil
	default:
		result := triaje.Inspect(data)
		details, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return nil, err
		}
		title, listing := result.Format, 0
		if len(result.Instructions) > 0 {
			title += " · Instrucciones"
			listing = 1
		}
		return []caso.Record{{
			Kind: "binario", Time: caso.Now(), Title: title,
			SHA256: result.SHA256, SourceID: sourceName(name), Details: string(details), BinaryListing: listing,
		}}, nil
	}
}

func sourceName(value string) string {
	value = strings.TrimSpace(value[strings.LastIndexAny(value, `/\`)+1:])
	if len(value) > 160 || !utf8.ValidString(value) || strings.ContainsFunc(value, func(char rune) bool {
		return unicode.IsControl(char) || unicode.In(char, unicode.Cf)
	}) || value == "." || value == ".." {
		return ""
	}
	return value
}

func Nota(title, source, details string) (caso.Record, error) {
	title, source, details = strings.TrimSpace(title), strings.TrimSpace(source), strings.TrimSpace(details)
	if title == "" || details == "" {
		return caso.Record{}, errors.New("introduce un título y una nota")
	}
	if len(title) > 160 || len(source) > 512 || len(details) > 8000 {
		return caso.Record{}, caso.ErrInvalidEdit
	}
	return caso.Record{Kind: "nota", Time: caso.Now(), Title: title, Source: source, Details: details}, nil
}
