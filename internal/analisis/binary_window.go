package analisis

import (
	"context"
	"crypto/sha256"
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
	Citation       BinaryWindowCitation     `json:"citation"`
	Window         triaje.InstructionWindow `json:"window"`
	Name           string                   `json:"name"`
	EntryAmbiguous bool                     `json:"entry_ambiguous,omitempty"`
}

type binaryWindowEvidence struct {
	record         caso.Record
	inspection     triaje.Binary
	inspectionHash string
	source         io.Reader
	data           []byte
	images         map[int]*triaje.InstructionImage
}

func openBinaryWindowEvidence(ctx context.Context, store *caso.Store, id string, revision int, source io.Reader) (*binaryWindowEvidence, error) {
	record, inspection, err := loadBinaryInspection(ctx, store, id, revision)
	if err != nil {
		return nil, err
	}
	return &binaryWindowEvidence{record: record, inspection: inspection, inspectionHash: caso.Hash([]byte(record.Details)),
		source: source, images: make(map[int]*triaje.InstructionImage)}, nil
}

func OpenBinaryWindow(ctx context.Context, store *caso.Store, request BinaryWindowRequest, source io.Reader) (BinaryWindowReport, error) {
	if _, valid := instructionPath(request.Path); !valid || request.RecordID == "" || request.Revision < 1 || request.Index < 0 {
		return BinaryWindowReport{}, ErrBinaryWindowRequest
	}
	evidence, err := openBinaryWindowEvidence(ctx, store, request.RecordID, request.Revision, source)
	if err != nil {
		return BinaryWindowReport{}, err
	}
	return evidence.window(ctx, request)
}

func (evidence *binaryWindowEvidence) window(ctx context.Context, request BinaryWindowRequest) (BinaryWindowReport, error) {
	steps, valid := instructionPath(request.Path)
	if !valid || request.Index < 0 {
		return BinaryWindowReport{}, ErrBinaryWindowRequest
	}
	report := &evidence.inspection
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
		if instructionCitationOffset(*report, request.Index) == "" {
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
	if err := evidence.readSample(ctx); err != nil {
		return BinaryWindowReport{}, err
	}
	if saved != nil {
		offset, _ := triaje.ParseBinaryHex(saved.Offset)
		if hex.EncodeToString(evidence.data[offset:offset+uint64(len(saved.Bytes)/2)]) != saved.Bytes {
			return BinaryWindowReport{}, triaje.ErrInstructionLocation
		}
	}
	decoded, err := evidence.image(image)
	if err != nil {
		return BinaryWindowReport{}, err
	}
	window, err := decoded.Window(symbol, steps...)
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
	citation := BinaryWindowCitation{Schema: BinaryWindowSchema, BinaryWindowRequest: request, SHA256: evidence.record.SHA256,
		InspectionSHA256: evidence.inspectionHash, WindowSHA256: caso.Hash(encoded), Image: image, Address: first.Address, Offset: first.Offset}
	return BinaryWindowReport{Citation: citation, Window: window, Name: name,
		EntryAmbiguous: request.Kind == "simbolo" && window.Origin == nil && !decoded.MatchesLocation(first.Address, first.Offset)}, nil
}

func (evidence *binaryWindowEvidence) readSample(ctx context.Context) error {
	if evidence.data != nil {
		return ctx.Err()
	}
	data, err := readVerifiedBinary(ctx, evidence.source, evidence.inspection.Size, evidence.record.SHA256)
	if err != nil {
		return err
	}
	evidence.data = data
	return nil
}

func readVerifiedBinary(ctx context.Context, source io.Reader, size int, digest string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if source == nil || size <= 0 || size > triaje.MaxBinaryBytes {
		return nil, ErrBinaryWindowSample
	}
	const blockSize = 64 << 10
	data := make([]byte, min(size, blockSize))
	hash := sha256.New()
	var eof bool
	for start := 0; start < size; start += blockSize {
		end := min(start+blockSize, size)
		block := data[start:end]
		n, err := readBinaryBlock(ctx, source, block)
		if canceled := ctx.Err(); canceled != nil {
			return nil, canceled
		}
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("leer el archivo original: %w", err)
		}
		eof = err == io.EOF
		if n != len(block) || (eof && end != size) {
			return nil, ErrBinaryWindowSample
		}
		_, _ = hash.Write(block)
		if len(data) < size {
			complete := make([]byte, size)
			copy(complete, data)
			data = complete
		}
	}
	if !eof {
		var extra [1]byte
		n, err := readBinaryBlock(ctx, source, extra[:])
		if canceled := ctx.Err(); canceled != nil {
			return nil, canceled
		}
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("leer el archivo original: %w", err)
		}
		if n != 0 {
			return nil, ErrBinaryWindowSample
		}
	}
	if hex.EncodeToString(hash.Sum(nil)) != digest {
		return nil, ErrBinaryWindowSample
	}
	return data, ctx.Err()
}

func readBinaryBlock(ctx context.Context, source io.Reader, block []byte) (int, error) {
	read := 0
	for read < len(block) {
		if err := ctx.Err(); err != nil {
			return read, err
		}
		n, err := source.Read(block[read:])
		read += n
		if err != nil {
			return read, err
		}
	}
	return read, nil
}

func (evidence *binaryWindowEvidence) image(index int) (*triaje.InstructionImage, error) {
	if decoded := evidence.images[index]; decoded != nil {
		return decoded, nil
	}
	decoded, err := triaje.OpenInstructionImage(evidence.data, index)
	if err == nil {
		evidence.images[index] = decoded
	}
	return decoded, err
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
