package analisis

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"pavarotti/internal/caso"
	"pavarotti/internal/triaje"
)

const BinaryWindowSchema = "pavarotti.binary-window-citation.v1"

var (
	ErrBinaryWindowRequest  = errors.New("indica una revisión, una ubicación y un recorrido válidos")
	ErrBinaryWindowSample   = errors.New("el tamaño o la huella SHA-256 del archivo difieren de la revisión guardada")
	ErrBinaryWindowCitation = errors.New("la ventana no coincide con la cita guardada")
)

type BinaryWindowRequest struct {
	RecordID string `json:"record_id"`
	Revision int    `json:"revision"`
	Kind     string `json:"kind"`
	Index    int    `json:"index"`
	Path     string `json:"path,omitempty"`
}

type BinaryWindowCitation struct {
	Schema string `json:"schema"`
	BinaryWindowRequest
	SHA256           string `json:"sha256"`
	InspectionSHA256 string `json:"inspection_sha256"`
	WindowSHA256     string `json:"window_sha256"`
	Image            int    `json:"image"`
	Address          string `json:"address"`
	Offset           string `json:"offset"`
}

type BinaryWindowReport struct {
	Citation BinaryWindowCitation     `json:"citation"`
	Window   triaje.InstructionWindow `json:"window"`
	Name     string                   `json:"name"`
}

func OpenBinaryWindow(ctx context.Context, store *caso.Store, request BinaryWindowRequest, source io.Reader) (BinaryWindowReport, error) {
	steps, valid := instructionPath(request.Path)
	if !valid || request.RecordID == "" || request.Revision < 1 || request.Index < 0 {
		return BinaryWindowReport{}, ErrBinaryWindowRequest
	}
	record, report, err := loadBinaryInspection(ctx, store, request.RecordID, request.Revision)
	if err != nil {
		return BinaryWindowReport{}, err
	}
	image := request.Index
	name := "Punto de entrada"
	var symbol *triaje.Symbol
	var saved *triaje.Instruction
	switch request.Kind {
	case "entrada":
	case "simbolo":
		if request.Index >= len(report.Symbols) || report.Symbols[request.Index].Offset == "" {
			return BinaryWindowReport{}, caso.ErrNotFound
		}
		symbol = &report.Symbols[request.Index]
		image, name = symbol.Image, symbol.Name
	case "instruccion":
		if instructionCitationOffset(report, request.Index) == "" {
			return BinaryWindowReport{}, caso.ErrNotFound
		}
		saved = &report.Instructions[request.Index]
		section := report.Sections[saved.Section]
		image, name = section.Image, "Instrucción guardada"
		symbol = &triaje.Symbol{Image: image, Section: section.Name, Address: saved.Address, Offset: saved.Offset}
	default:
		return BinaryWindowReport{}, ErrBinaryWindowRequest
	}
	if image < 0 || (len(report.Images) == 0 && image != 0) || (len(report.Images) > 0 && (image == 0 || image > len(report.Images))) {
		return BinaryWindowReport{}, ErrBinaryWindowRequest
	}
	if report.Size <= 0 || report.Size > triaje.MaxBinaryBytes {
		return BinaryWindowReport{}, ErrBinaryWindowSample
	}
	data, err := io.ReadAll(io.LimitReader(source, int64(report.Size)+1))
	if err != nil {
		return BinaryWindowReport{}, fmt.Errorf("leer el archivo original: %w", err)
	}
	if len(data) != report.Size || caso.Hash(data) != record.SHA256 {
		return BinaryWindowReport{}, ErrBinaryWindowSample
	}
	if saved != nil {
		offset, _ := triaje.ParseBinaryHex(saved.Offset)
		if hex.EncodeToString(data[offset:offset+uint64(len(saved.Bytes)/2)]) != saved.Bytes {
			return BinaryWindowReport{}, triaje.ErrInstructionLocation
		}
	}
	if err := ctx.Err(); err != nil {
		return BinaryWindowReport{}, err
	}
	window, err := triaje.OpenInstructionWindow(data, image, symbol, steps...)
	if err != nil {
		return BinaryWindowReport{}, err
	}
	encoded, err := json.Marshal(window)
	if err != nil {
		return BinaryWindowReport{}, err
	}
	first := window.Instructions[0]
	if window.Origin != nil {
		name = "Destino directo"
	}
	citation := BinaryWindowCitation{Schema: BinaryWindowSchema, BinaryWindowRequest: request, SHA256: record.SHA256,
		InspectionSHA256: caso.Hash([]byte(record.Details)), WindowSHA256: caso.Hash(encoded), Image: image, Address: first.Address, Offset: first.Offset}
	return BinaryWindowReport{Citation: citation, Window: window, Name: name}, nil
}

func instructionPath(path string) ([]int, bool) {
	if path == "" {
		return nil, true
	}
	if len(path) > triaje.MaxInstructionSteps*3-1 {
		return nil, false
	}
	parts := strings.Split(path, ".")
	if len(parts) > triaje.MaxInstructionSteps {
		return nil, false
	}
	steps := make([]int, 0, len(parts))
	for _, part := range parts {
		index, err := strconv.Atoi(part)
		if err != nil || index < 0 || index >= triaje.MaxWindowInstructions || strconv.Itoa(index) != part {
			return nil, false
		}
		steps = append(steps, index)
	}
	return steps, true
}

func VerifyBinaryWindow(ctx context.Context, store *caso.Store, citation BinaryWindowCitation, source io.Reader) (BinaryWindowReport, error) {
	if citation.Schema != BinaryWindowSchema {
		return BinaryWindowReport{}, ErrBinaryWindowCitation
	}
	report, err := OpenBinaryWindow(ctx, store, citation.BinaryWindowRequest, source)
	if err == nil && report.Citation != citation {
		return BinaryWindowReport{}, ErrBinaryWindowCitation
	}
	return report, err
}
