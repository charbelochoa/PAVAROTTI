package analisis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"pavarotti/internal/caso"
	"pavarotti/internal/triaje"
)

const BinaryWindowSchema = "pavarotti.binary-window-citation.v1"

var (
	ErrBinaryWindowRequest  = errors.New("indica la revisión y el índice del símbolo o de la imagen")
	ErrBinaryWindowSample   = errors.New("el tamaño o la huella SHA-256 del archivo difieren de la revisión guardada")
	ErrBinaryWindowCitation = errors.New("la ventana no coincide con la cita guardada")
)

type BinaryWindowRequest struct {
	RecordID string `json:"record_id"`
	Revision int    `json:"revision"`
	Kind     string `json:"kind"`
	Index    int    `json:"index"`
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
	if request.RecordID == "" || request.Revision < 1 || request.Index < 0 || (request.Kind != "simbolo" && request.Kind != "entrada") {
		return BinaryWindowReport{}, ErrBinaryWindowRequest
	}
	record, report, err := loadBinaryInspection(ctx, store, request.RecordID, request.Revision)
	if err != nil {
		return BinaryWindowReport{}, err
	}
	image := request.Index
	name := "Punto de entrada"
	var symbol *triaje.Symbol
	if request.Kind == "simbolo" {
		if request.Index >= len(report.Symbols) || report.Symbols[request.Index].Offset == "" {
			return BinaryWindowReport{}, caso.ErrNotFound
		}
		symbol = &report.Symbols[request.Index]
		image, name = symbol.Image, symbol.Name
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
	if err := ctx.Err(); err != nil {
		return BinaryWindowReport{}, err
	}
	window, err := triaje.OpenInstructionWindow(data, image, symbol)
	if err != nil {
		return BinaryWindowReport{}, err
	}
	encoded, err := json.Marshal(window)
	if err != nil {
		return BinaryWindowReport{}, err
	}
	first := window.Instructions[0]
	citation := BinaryWindowCitation{Schema: BinaryWindowSchema, BinaryWindowRequest: request, SHA256: record.SHA256,
		InspectionSHA256: caso.Hash([]byte(record.Details)), WindowSHA256: caso.Hash(encoded), Image: image, Address: first.Address, Offset: first.Offset}
	return BinaryWindowReport{Citation: citation, Window: window, Name: name}, nil
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
