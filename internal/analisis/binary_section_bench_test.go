package analisis

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"testing"

	"pavarotti/internal/caso"
	"pavarotti/internal/triaje"
)

func BenchmarkBinarySectionVerification(b *testing.B) {
	for _, scenario := range []struct {
		size     int
		sections int
	}{{256 << 10, 16}, {4 << 20, 64}, {triaje.MaxBinaryBytes, 256}} {
		b.Run(fmt.Sprint(scenario.size>>10)+"KiB", func(b *testing.B) {
			store := openScaleStore(b, "local")
			base := sectionScalePE(b, scenario.size, scenario.sections, false)
			current := sectionScalePE(b, scenario.size, scenario.sections, true)
			baseTarget := saveSectionScaleRecord(b, store, "base.exe", base)
			currentTarget := saveSectionScaleRecord(b, store, "actual.exe", current)
			b.ReportAllocs()
			for b.Loop() {
				var reader BinarySectionReader
				before, err := reader.Read(b.Context(), store, baseTarget, bytes.NewReader(base))
				if err != nil {
					b.Fatal(err)
				}
				after, err := reader.Read(b.Context(), store, currentTarget, bytes.NewReader(current))
				if err != nil {
					b.Fatal(err)
				}
				comparison, err := CompareBinarySections(before, after)
				if err != nil || len(comparison.Rows) != scenario.sections {
					b.Fatalf("comparación de %d secciones: %v", len(comparison.Rows), err)
				}
				if comparison.Rows[0].State != "modificada" || comparison.Rows[1].State != "movida" || comparison.Rows[2].State != "igual" {
					b.Fatalf("estados de sección: %+v", comparison.Rows[:3])
				}
			}
		})
	}
}

func sectionScalePE(tb testing.TB, size, sections int, current bool) []byte {
	tb.Helper()
	data := make([]byte, size)
	const tableStart = 0x188
	const firstFileOffset = 0x4000
	const firstAddress = 0x1000
	sectionSize := (size - firstFileOffset) / sections
	order := binary.LittleEndian
	copy(data, "MZ")
	order.PutUint32(data[0x3c:], 0x80)
	copy(data[0x80:], "PE\x00\x00")
	order.PutUint16(data[0x84:], pe.IMAGE_FILE_MACHINE_AMD64)
	order.PutUint16(data[0x86:], uint16(sections))
	optional := pe.OptionalHeader64{Magic: 0x20b, NumberOfRvaAndSizes: 16}
	order.PutUint16(data[0x94:], uint16(binary.Size(optional)))
	if _, err := binary.Encode(data[0x98:], order, optional); err != nil {
		tb.Fatal(err)
	}
	for index := range sections {
		header := data[tableStart+40*index:]
		copy(header[:8], fmt.Sprintf(".s%03d", index))
		start := firstFileOffset + index*sectionSize
		address := firstAddress + index*sectionSize
		if current && index%4 == 1 {
			address++
		}
		order.PutUint32(header[8:], uint32(sectionSize))
		order.PutUint32(header[12:], uint32(address))
		order.PutUint32(header[16:], uint32(sectionSize))
		order.PutUint32(header[20:], uint32(start))
		data[start] = byte(index)
		if current && index%4 == 0 {
			data[start+sectionSize-1] = 1
		}
	}
	return data
}

func saveSectionScaleRecord(tb testing.TB, store *caso.Store, name string, data []byte) BinarySectionTarget {
	tb.Helper()
	inspection := triaje.Inspect(data)
	encoded, err := json.Marshal(inspection)
	if err != nil {
		tb.Fatal(err)
	}
	if err := store.Save([]caso.Record{{Kind: "binario", SHA256: inspection.SHA256, Title: name, SourceID: name, Details: string(encoded)}}); err != nil {
		tb.Fatal(err)
	}
	page, err := store.Page(tb.Context(), caso.PageRequest{Kind: "binario"})
	if err != nil {
		tb.Fatal(err)
	}
	for _, row := range page.Rows {
		if row.SourceID == name {
			return BinarySectionTarget{RecordID: row.ID, Revision: 1}
		}
	}
	tb.Fatalf("muestra %s ausente", name)
	return BinarySectionTarget{}
}
