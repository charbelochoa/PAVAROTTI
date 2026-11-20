package analisis

import (
	"bytes"
	"context"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"pavarotti/internal/caso"
	"pavarotti/internal/ingesta"
	"pavarotti/internal/triaje"
)

func TestLargeSectionInventoriesRetainExactCitations(t *testing.T) {
	for _, format := range []string{"ELF", "Mach-O universal"} {
		t.Run(format, func(t *testing.T) {
			pair := openSectionFormatPair(t, format)
			result, err := pair.compare(t.Context())
			if err != nil || len(result.Rows) != 256 || result.Baseline.Format != format || result.Current.Format != format {
				t.Fatalf("%s: %d secciones, %v", format, len(result.Rows), err)
			}
			name, architecture := ".s253", elf.EM_X86_64.String()
			if format == "Mach-O universal" {
				name, architecture = "__DATA/__s191", macho.CpuAmd64.String()
			}
			index := slices.IndexFunc(result.Rows, func(row BinarySectionChange) bool {
				return row.Name == name && row.Architecture == architecture
			})
			if index == -1 {
				t.Fatalf("sección ausente: %s", name)
			}
			row := result.Rows[index]
			if row.State != "movida" || len(row.Baseline) != 1 || len(row.Current) != 1 || row.Baseline[0].SHA256 != row.Current[0].SHA256 {
				t.Fatalf("sección: %+v", row)
			}
			if format == "Mach-O universal" && (row.Baseline[0].Image != 1 || row.Current[0].Image != 2 || row.Subtype != "0x3") {
				t.Fatalf("imágenes reordenadas: %+v", row)
			}
			for index, entry := range []BinarySectionEntry{row.Baseline[0], row.Current[0]} {
				if entry.Citation == nil || entry.Citation.RecordID != pair.targets[index].RecordID {
					t.Fatalf("cita de sección: %+v", entry)
				}
				cite, err := CiteBinary(t.Context(), pair.store, entry.Citation.RecordID, 1, "seccion", entry.Index)
				if err != nil || cite != *entry.Citation {
					t.Fatalf("cita de sección: %+v, %v", cite, err)
				}
			}
		})
	}
}

func TestUniversalSectionsCanBeReimportedWithoutChangingOldCitations(t *testing.T) {
	data := sectionScaleUniversal(t, 128<<10, 192, 64, false)
	legacy := triaje.Inspect(data)
	if !legacy.RestoresUniversalSections() || len(legacy.Sections) != 256 {
		t.Fatalf("inventario: %d secciones, recuperación %t", len(legacy.Sections), legacy.RestoresUniversalSections())
	}
	legacy.Sections = slices.Concat(legacy.Sections[:128], legacy.Sections[192:])
	encoded, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	legacyRecord := caso.Record{Kind: "binario", SHA256: legacy.SHA256, Title: legacy.Format, Details: string(encoded)}
	for _, backend := range []string{"local", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			store := openScaleStore(t, backend)
			if err := store.Save([]caso.Record{legacyRecord}); err != nil {
				t.Fatal(err)
			}
			ctx := t.Context()
			id := caso.Hash([]byte("binario:"+legacy.SHA256)) + "-1"
			old, err := CiteBinary(ctx, store, id, 1, "seccion", 191)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ReadBinarySections(ctx, store, BinarySectionTarget{id, 1}, bytes.NewReader(data)); !errors.Is(err, ErrBinarySectionInventory) || !strings.Contains(err.Error(), "vuelve a importar") {
				t.Fatalf("inventario anterior: %v", err)
			}
			records, err := ingesta.ParseNamed("binario", bytes.NewReader(data), "universal.bin")
			if err != nil || len(records) != 1 || !strings.Contains(records[0].Title, "Secciones completas") {
				t.Fatalf("nueva inspección: %v", err)
			}
			if result, err := store.SaveEvidence(ctx, records); err != nil || result.Imported != 1 {
				t.Fatalf("reimportación: %+v, %v", result, err)
			}
			if result, err := store.SaveEvidence(ctx, records); err != nil || result.Duplicates != 1 {
				t.Fatalf("reimportación repetida: %+v, %v", result, err)
			}
			if cite, err := CiteBinary(ctx, store, id, 1, "seccion", 191); err != nil || cite != old {
				t.Fatalf("cita original: %+v, %v", cite, err)
			}
			page, err := store.Page(ctx, caso.PageRequest{Kind: "binario"})
			if err != nil || len(page.Rows) != 2 {
				t.Fatalf("inspecciones: %d, %v", len(page.Rows), err)
			}
			for _, row := range page.Rows {
				if row.ID != id {
					inventory, err := ReadBinarySections(ctx, store, BinarySectionTarget{row.ID, 1}, bytes.NewReader(data))
					if err != nil || inventory.source.Sections != 256 {
						t.Fatalf("inventario completo: %d secciones, %v", inventory.source.Sections, err)
					}
				}
			}
		})
	}
	bounded := triaje.Inspect(sectionScaleUniversal(t, 128<<10, 193, 64, false))
	if bounded.SectionCount != 257 || len(bounded.Sections) > 256 || bounded.RestoresUniversalSections() {
		t.Fatalf("límite de inventario: %d de %d secciones", len(bounded.Sections), bounded.SectionCount)
	}
}

func BenchmarkLargeSectionFormats(b *testing.B) {
	for _, format := range []string{"ELF", "Mach-O universal"} {
		b.Run(format, func(b *testing.B) {
			pair := openSectionFormatPair(b, format)
			b.ReportAllocs()
			for b.Loop() {
				result, err := pair.compare(b.Context())
				if err != nil || len(result.Rows) != 256 {
					b.Fatalf("%s: %d secciones, %v", format, len(result.Rows), err)
				}
			}
		})
	}
}

type sectionFormatPair struct {
	store   *caso.Store
	samples [2][]byte
	targets [2]BinarySectionTarget
}

func openSectionFormatPair(tb testing.TB, format string) sectionFormatPair {
	tb.Helper()
	pair := sectionFormatPair{store: openScaleStore(tb, "local")}
	for index, name := range []string{"base", "actual"} {
		if format == "ELF" {
			pair.samples[index] = sectionScaleELF(triaje.MaxBinaryBytes, index == 1)
		} else {
			pair.samples[index] = sectionScaleUniversal(tb, triaje.MaxBinaryBytes, 192, 64, index == 1)
		}
		pair.targets[index] = saveSectionScaleRecord(tb, pair.store, name, pair.samples[index])
	}
	return pair
}

func (pair sectionFormatPair) compare(ctx context.Context) (BinarySectionComparison, error) {
	var reader BinarySectionReader
	var inventory [2]BinarySectionInventory
	for index, sample := range pair.samples {
		sections, err := reader.Read(ctx, pair.store, pair.targets[index], bytes.NewReader(sample))
		if err != nil {
			return BinarySectionComparison{}, err
		}
		inventory[index] = sections
	}
	return CompareBinarySections(inventory[0], inventory[1])
}

func sectionScaleELF(size int, current bool) []byte {
	const sectionTable, stringTable, firstData = 0x100, 0x5000, 0x6000
	const sections, entries = 256, 254
	data := make([]byte, size)
	order := binary.LittleEndian
	copy(data, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	order.PutUint16(data[16:], uint16(elf.ET_REL))
	order.PutUint16(data[18:], uint16(elf.EM_X86_64))
	order.PutUint32(data[20:], 1)
	order.PutUint64(data[40:], sectionTable)
	order.PutUint16(data[52:], 64)
	order.PutUint16(data[58:], 64)
	order.PutUint16(data[60:], sections)
	order.PutUint16(data[62:], 1)
	names := []byte("\x00.shstrtab\x00")
	sectionSize := (size - firstData) / entries
	for index := range entries {
		header := data[sectionTable+64*(index+2):]
		order.PutUint32(header, uint32(len(names)))
		order.PutUint32(header[4:], uint32(elf.SHT_PROGBITS))
		names = fmt.Appendf(names, ".s%03d\x00", index)
		offset := firstData + index*sectionSize
		address := 0x1000 + index*sectionSize
		if current && index%4 == 1 {
			address++
		}
		order.PutUint64(header[16:], uint64(address))
		order.PutUint64(header[24:], uint64(offset))
		order.PutUint64(header[32:], uint64(sectionSize))
		order.PutUint64(header[48:], 1)
		data[offset] = byte(index)
		if current && index%4 == 0 {
			data[offset+sectionSize-1] = 1
		}
	}
	stringsHeader := data[sectionTable+64:]
	order.PutUint32(stringsHeader, 1)
	order.PutUint32(stringsHeader[4:], uint32(elf.SHT_STRTAB))
	order.PutUint64(stringsHeader[24:], stringTable)
	order.PutUint64(stringsHeader[32:], uint64(len(names)))
	order.PutUint64(stringsHeader[48:], 1)
	copy(data[stringTable:], names)
	return data
}

func sectionScaleUniversal(tb testing.TB, size, amdSections, armSections int, reversed bool) []byte {
	tb.Helper()
	data := make([]byte, size)
	order := binary.BigEndian
	order.PutUint32(data, 0xcafebabf)
	order.PutUint32(data[4:], 2)
	images := []struct {
		cpu      macho.Cpu
		subtype  uint32
		sections int
	}{{macho.CpuAmd64, 3, amdSections}, {macho.CpuArm64, 0, armSections}}
	if reversed {
		slices.Reverse(images)
	}
	for index, image := range images {
		offset := size/2*index + 0x1000
		region := data[offset : size/2*(index+1)]
		fat := data[8+32*index:]
		order.PutUint32(fat, uint32(image.cpu))
		order.PutUint32(fat[4:], image.subtype)
		order.PutUint64(fat[8:], uint64(offset))
		order.PutUint64(fat[16:], uint64(len(region)))
		order.PutUint32(fat[24:], 12)
		segment := macho.Segment64{Cmd: macho.LoadCmdSegment64, Memsz: uint64(len(region)), Filesz: uint64(len(region)), Nsect: uint32(image.sections)}
		segment.Len = uint32(binary.Size(segment) + image.sections*binary.Size(macho.Section64{}))
		copy(segment.Name[:], "__DATA")
		header := macho.FileHeader{Magic: macho.Magic64, Cpu: image.cpu, SubCpu: image.subtype, Type: macho.TypeObj, Ncmd: 1, Cmdsz: segment.Len}
		buffer := bytes.NewBuffer(region[:0])
		for _, item := range []any{header, uint32(0), segment} {
			if err := binary.Write(buffer, binary.LittleEndian, item); err != nil {
				tb.Fatal(err)
			}
		}
		const firstData = 0x4000
		sectionSize := (len(region) - firstData) / image.sections
		for section := range image.sections {
			position := firstData + section*sectionSize
			item := macho.Section64{Addr: uint64(0x1000 + section*sectionSize), Size: uint64(sectionSize), Offset: uint32(position)}
			copy(item.Name[:], fmt.Sprintf("__s%03d", section))
			copy(item.Seg[:], "__DATA")
			if err := binary.Write(buffer, binary.LittleEndian, item); err != nil {
				tb.Fatal(err)
			}
			region[position] = byte(section)
			if reversed && image.cpu == macho.CpuArm64 && section == image.sections-1 {
				region[position+sectionSize-1] = 1
			}
		}
	}
	return data
}
