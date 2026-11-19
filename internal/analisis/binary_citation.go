package analisis

import (
	"context"
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
	if id == "" || revision < 1 || index < 0 || (kind != "seccion" && kind != "cadena" && kind != "simbolo") {
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
	position, err := strconv.ParseUint(strings.TrimPrefix(offset, "0x"), 16, 64)
	if err != nil || !strings.HasPrefix(offset, "0x") || report.Size <= 0 || position >= uint64(report.Size) {
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
	}
	return ""
}
