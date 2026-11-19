package analisis

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"pavarotti/internal/caso"
	"pavarotti/internal/triaje"
)

const BinaryCitationSchema = "pavarotti.binary-citation.v1"

var ErrBinaryCitation = errors.New("indica una revisión, un tipo de cita y un índice válidos")

type BinaryCitation struct {
	Schema           string `json:"schema"`
	RecordID         string `json:"record_id"`
	Revision         int    `json:"revision"`
	SHA256           string `json:"sha256"`
	InspectionSHA256 string `json:"inspection_sha256"`
	Kind             string `json:"kind"`
	Index            int    `json:"index"`
	Offset           string `json:"offset"`
}

func CiteBinary(ctx context.Context, store *caso.Store, id string, revision int, kind string, index int) (BinaryCitation, error) {
	if id == "" || revision < 1 || index < 0 || (kind != "seccion" && kind != "cadena" && kind != "simbolo" && kind != "instruccion") {
		return BinaryCitation{}, ErrBinaryCitation
	}
	record, err := store.RecordRevision(ctx, id, revision)
	if err != nil {
		return BinaryCitation{}, err
	}
	var report triaje.Binary
	if record.Kind != "binario" || record.SHA256 == "" || json.Unmarshal([]byte(record.Details), &report) != nil || report.SHA256 != record.SHA256 {
		return BinaryCitation{}, caso.ErrNotFound
	}
	offset := binaryCitationOffset(report, kind, index)
	position, valid := parseBinaryHex(offset)
	if !valid || report.Size <= 0 || position >= uint64(report.Size) {
		return BinaryCitation{}, caso.ErrNotFound
	}
	return BinaryCitation{Schema: BinaryCitationSchema, RecordID: record.ID, Revision: record.Revision, SHA256: record.SHA256,
		InspectionSHA256: caso.Hash([]byte(record.Details)), Kind: kind, Index: index, Offset: offset}, nil
}

func binaryCitationOffset(report triaje.Binary, kind string, index int) string {
	switch kind {
	case "seccion":
		if index < len(report.Sections) && report.Sections[index].File != nil {
			return report.Sections[index].File.Offset
		}
	case "cadena":
		if index < len(report.Strings) {
			return report.Strings[index].Offset
		}
	case "simbolo":
		if index < len(report.Symbols) {
			return report.Symbols[index].Offset
		}
	case "instruccion":
		return instructionCitationOffset(report, index)
	}
	return ""
}

func instructionCitationOffset(report triaje.Binary, index int) string {
	if index >= len(report.Instructions) || report.Size <= 0 {
		return ""
	}
	inst := report.Instructions[index]
	if inst.Section < 0 || inst.Section >= len(report.Sections) || len(inst.Bytes) == 0 || len(inst.Bytes) > 30 {
		return ""
	}
	section := report.Sections[inst.Section]
	if section.File == nil {
		return ""
	}
	code, err := hex.DecodeString(inst.Bytes)
	position, validPosition := parseBinaryHex(inst.Offset)
	start, validStart := parseBinaryHex(section.File.Offset)
	address, validAddress := parseBinaryHex(inst.Address)
	base, validBase := parseBinaryHex(section.Address)
	if err != nil || !validPosition || !validStart || !validAddress || !validBase ||
		position < start || start >= uint64(report.Size) || section.File.Size > uint64(report.Size)-start || address < base {
		return ""
	}
	delta := position - start
	if delta >= section.File.Size || uint64(len(code)) > section.File.Size-delta || address-base != delta {
		return ""
	}
	return inst.Offset
}

func parseBinaryHex(value string) (uint64, bool) {
	digits, ok := strings.CutPrefix(value, "0x")
	if !ok {
		return 0, false
	}
	position, err := strconv.ParseUint(digits, 16, 64)
	return position, err == nil
}
