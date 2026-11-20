package analisis

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"slices"
	"testing"

	"pavarotti/internal/caso"
	"pavarotti/internal/triaje"
)

func BenchmarkBinaryReferenceVerification(b *testing.B) {
	for _, scenario := range []struct {
		origins int
		bytes   int
	}{{64, 64 << 10}, {1024, 4 << 20}, {maxBinaryReferenceOrigins, triaje.MaxBinaryBytes}} {
		b.Run(fmt.Sprint(scenario.origins), func(b *testing.B) {
			store, sample, draft := binaryReferenceScale(b, scenario.origins, scenario.bytes)
			baseline := sealScaleReferences(b, store, sample, draft)
			removed := len(draft.Origins) / 16
			draft.Origins = slices.Clone(draft.Origins[removed:])
			slices.Reverse(draft.Origins)
			current := sealScaleReferences(b, store, sample, draft)
			b.ReportAllocs()
			for b.Loop() {
				comparison, err := CompareBinaryReferences(b.Context(), store, baseline, current, bytes.NewReader(sample))
				if err != nil || len(comparison.Rows) != scenario.origins || comparison.Shared != len(current.Origins) ||
					comparison.Absent != removed || comparison.Added != 0 {
					b.Fatalf("comparación: %d filas, %d comunes, %d ausentes, %v", len(comparison.Rows), comparison.Shared, comparison.Absent, err)
				}
			}
		})
	}
}

func binaryReferenceScale(tb testing.TB, count, size int) (*caso.Store, []byte, BinaryReferenceReport) {
	tb.Helper()
	const codeOffset, codeAddress, instructionBytes = 0x200, 0x1000, 5
	windows := (count + triaje.MaxWindowInstructions - 1) / triaje.MaxWindowInstructions
	codeSize := count*instructionBytes + 1
	symbolOffset := codeOffset + codeSize
	data := make([]byte, size)
	order := binary.LittleEndian
	copy(data, "MZ")
	order.PutUint32(data[0x3c:], 0x80)
	copy(data[0x80:], "PE\x00\x00")
	order.PutUint16(data[0x84:], pe.IMAGE_FILE_MACHINE_AMD64)
	order.PutUint16(data[0x86:], 1)
	order.PutUint32(data[0x8c:], uint32(symbolOffset))
	order.PutUint32(data[0x90:], uint32(windows+1))
	header := pe.OptionalHeader64{Magic: 0x20b, AddressOfEntryPoint: codeAddress, NumberOfRvaAndSizes: 16}
	order.PutUint16(data[0x94:], uint16(binary.Size(header)))
	if _, err := binary.Encode(data[0x98:], order, header); err != nil {
		tb.Fatal(err)
	}
	section := data[0x98+binary.Size(header):]
	copy(section, ".text")
	order.PutUint32(section[8:], uint32(codeSize))
	order.PutUint32(section[12:], codeAddress)
	order.PutUint32(section[16:], uint32(codeSize))
	order.PutUint32(section[20:], codeOffset)
	order.PutUint32(section[36:], pe.IMAGE_SCN_MEM_EXECUTE)
	for i := range count {
		start := i * instructionBytes
		data[codeOffset+start] = 0xe9
		order.PutUint32(data[codeOffset+start+1:], uint32(codeSize-1-start-instructionBytes))
	}
	data[symbolOffset-1] = 0xc3
	for i := 0; i <= windows; i++ {
		symbol := data[symbolOffset+i*18:]
		copy(symbol, fmt.Sprintf("span%04d", i))
		start := min(count, i*triaje.MaxWindowInstructions) * instructionBytes
		order.PutUint32(symbol[8:], uint32(start))
		order.PutUint16(symbol[12:], 1)
		order.PutUint16(symbol[14:], 0x20)
		symbol[16] = 2
	}
	order.PutUint32(data[symbolOffset+(windows+1)*18:], 4)
	inspection := triaje.Inspect(data)
	if inspection.Format != "PE" || len(inspection.Symbols) != windows+1 {
		tb.Fatalf("inspección: %s, %d símbolos", inspection.Format, len(inspection.Symbols))
	}
	store := openScaleStore(tb, "local")
	encoded, err := json.Marshal(inspection)
	if err != nil {
		tb.Fatal(err)
	}
	if err := store.Save([]caso.Record{{Kind: "binario", SHA256: inspection.SHA256, Title: "Muestra sintética PE", Details: string(encoded)}}); err != nil {
		tb.Fatal(err)
	}
	page, err := store.Page(tb.Context(), caso.PageRequest{Kind: "binario"})
	if err != nil || len(page.Rows) != 1 {
		tb.Fatalf("muestra: %d registros, %v", len(page.Rows), err)
	}
	location := func(index, row, delta int) BinaryReferenceLocation {
		return BinaryReferenceLocation{Kind: "simbolo", Index: index, Row: row,
			Address: fmt.Sprintf("0x%x", codeAddress+delta), Offset: fmt.Sprintf("0x%x", codeOffset+delta)}
	}
	draft := BinaryReferenceReport{Schema: BinaryReferenceSchema, RecordID: page.Rows[0].ID, Revision: 1, SHA256: inspection.SHA256,
		Destination: location(windows, 0, codeSize-1), Origins: make([]BinaryReferenceLocation, 0, count)}
	for index := range count {
		draft.Origins = append(draft.Origins, location(index/triaje.MaxWindowInstructions, index%triaje.MaxWindowInstructions, index*instructionBytes))
	}
	return store, data, draft
}

func sealScaleReferences(tb testing.TB, store *caso.Store, sample []byte, draft BinaryReferenceReport) BinaryReferenceReport {
	tb.Helper()
	review, err := ReviewBinaryReferences(tb.Context(), store, draft, bytes.NewReader(sample), false)
	if err != nil {
		tb.Fatal(err)
	}
	return review.Report
}
