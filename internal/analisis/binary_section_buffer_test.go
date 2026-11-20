package analisis

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"pavarotti/internal/caso"
)

func TestBinarySectionReaderPreservesBothInventoriesWhenReusingStorage(t *testing.T) {
	store := openScaleStore(t, "local")
	const size, sections = 256 << 10, 16
	base := sectionScalePE(t, size, sections, false)
	current := sectionScalePE(t, size, sections, true)
	baseTarget := saveSectionScaleRecord(t, store, "base.exe", base)
	currentTarget := saveSectionScaleRecord(t, store, "actual.exe", current)
	ctx := t.Context()
	var reader BinarySectionReader
	before, err := reader.Read(ctx, store, baseTarget, bytes.NewReader(base))
	if err != nil || len(reader.original) != len(base) {
		t.Fatalf("inventario base: %d bytes, %v", len(reader.original), err)
	}
	allocated := &reader.original[0]
	if _, err := reader.Read(ctx, store, currentTarget, bytes.NewReader(base)); !errors.Is(err, ErrBinaryWindowSample) {
		t.Fatalf("original de otra revisión: %v", err)
	}
	after, err := reader.Read(ctx, store, currentTarget, bytes.NewReader(current))
	if err != nil || &reader.original[0] != allocated {
		t.Fatalf("almacenamiento reutilizado: %v", err)
	}
	expected, err := ReadBinarySections(ctx, store, baseTarget, bytes.NewReader(base))
	if err != nil || !reflect.DeepEqual(before, expected) {
		t.Fatalf("inventario base alterado al reutilizar almacenamiento: %v", err)
	}
	result, err := CompareBinarySections(before, after)
	if err != nil || len(result.Rows) != sections || result.Rows[0].State != "modificada" ||
		result.Baseline.SHA256 != caso.Hash(base) || result.Current.SHA256 != caso.Hash(current) {
		t.Fatalf("resultado de ambas revisiones: %+v, %v", result, err)
	}
	row := result.Rows[0]
	for _, entry := range []BinarySectionEntry{row.Baseline[0], row.Current[0]} {
		citation := entry.Citation
		if citation == nil {
			t.Fatal("falta la cita de sección")
		}
		verified, err := CiteBinary(ctx, store, citation.RecordID, citation.Revision, citation.Kind, citation.Index)
		if err != nil || verified != *citation {
			t.Fatalf("cita de sección: %+v, %v", citation, err)
		}
	}
}
