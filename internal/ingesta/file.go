package ingesta

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"pavarotti/internal/caso"
	"pavarotti/internal/revision"
	"pavarotti/internal/trafico"
	"pavarotti/internal/triaje"
)

const MaxBytes = 32 << 20

var (
	ErrKind = errors.New("tipo de archivo desconocido, usa har, hallazgos, binario, codigo, indicadores, dns, rdap o stix")
	ErrSize = errors.New("el archivo supera el límite de 32 MiB")
)

func Parse(kind string, reader io.Reader) ([]caso.Record, error) {
	switch kind {
	case "har", "hallazgos", "binario", "codigo", "indicadores", "dns", "rdap", "stix":
	default:
		return nil, ErrKind
	}

	data, err := io.ReadAll(io.LimitReader(reader, MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("leer archivo: %w", err)
	}
	if len(data) > MaxBytes {
		return nil, ErrSize
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
			SHA256: caso.Hash(data), Details: string(details), Signals: signals}}, nil
	default:
		result := triaje.Inspect(data)
		details, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return nil, err
		}
		return []caso.Record{{
			Kind: "binario", Time: caso.Now(), Title: result.Format,
			SHA256: result.SHA256, Details: string(details),
		}}, nil
	}
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
