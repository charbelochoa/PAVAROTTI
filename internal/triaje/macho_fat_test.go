package triaje

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"slices"
	"testing"
)

func thinMachOFixture(t *testing.T, cpu macho.Cpu, subtype, sectionOffset uint32) []byte {
	t.Helper()
	const name = "sample_entry"
	section := macho.Section64{Addr: 0x1000, Size: 16, Offset: sectionOffset}
	copy(section.Name[:], "__text")
	copy(section.Seg[:], "__TEXT")
	segment := macho.Segment64{Cmd: macho.LoadCmdSegment64, Addr: 0x1000, Memsz: 0x200, Filesz: 0x200, Nsect: 1}
	segment.Len = uint32(binary.Size(segment) + binary.Size(section))
	copy(segment.Name[:], "__TEXT")
	symtab := macho.SymtabCmd{Cmd: macho.LoadCmdSymtab, Len: 24, Symoff: 0x140, Nsyms: 1, Stroff: 0x150, Strsize: uint32(len(name) + 2)}
	header := macho.FileHeader{Magic: macho.Magic64, Cpu: cpu, SubCpu: subtype, Type: macho.TypeExec, Ncmd: 2, Cmdsz: segment.Len + symtab.Len}
	data := make([]byte, 0x200)
	out := bytes.NewBuffer(data[:0])
	for _, item := range []any{header, uint32(0), segment, section, symtab} {
		if err := binary.Write(out, binary.LittleEndian, item); err != nil {
			t.Fatal(err)
		}
	}
	sym := bytes.NewBuffer(data[0x140:0x140])
	if err := binary.Write(sym, binary.LittleEndian, macho.Nlist64{Name: 1, Type: 0x0f, Sect: 1, Value: 0x1008}); err != nil {
		t.Fatal(err)
	}
	copy(data[0x151:], name)
	return data
}

func fatMachOFixture(t *testing.T, wide, swapped bool, first, second []byte) []byte {
	t.Helper()
	data := make([]byte, 0x4000)
	var order binary.ByteOrder = binary.BigEndian
	if swapped {
		order = binary.LittleEndian
	}
	magic, entrySize := macho.MagicFat, 20
	if wide {
		magic, entrySize = machOFat64, 32
	}
	order.PutUint32(data, magic)
	order.PutUint32(data[4:], 2)
	for index, inner := range [][]byte{first, second} {
		entry := data[8+index*entrySize:]
		order.PutUint32(entry, binary.LittleEndian.Uint32(inner[4:]))
		order.PutUint32(entry[4:], binary.LittleEndian.Uint32(inner[8:]))
		offset := 0x1000 + index*0x2000
		if wide {
			order.PutUint64(entry[8:], uint64(offset))
			order.PutUint64(entry[16:], uint64(len(inner)))
			order.PutUint32(entry[24:], 12)
		} else {
			order.PutUint32(entry[8:], uint32(offset))
			order.PutUint32(entry[12:], uint32(len(inner)))
			order.PutUint32(entry[16:], 12)
		}
		copy(data[offset:], inner)
	}
	return data
}

func TestMachOFatUsesContainerOffsetsInBothImages(t *testing.T) {
	first := thinMachOFixture(t, macho.CpuAmd64, 3, 0x100)
	second := thinMachOFixture(t, macho.CpuArm64, 0, 0x100)
	for _, fixture := range []struct {
		name          string
		wide, swapped bool
	}{{"FAT", false, false}, {"FAT64", true, false}, {"FAT intercambiado", false, true}, {"FAT64 intercambiado", true, true}} {
		t.Run(fixture.name, func(t *testing.T) {
			result := Inspect(fatMachOFixture(t, fixture.wide, fixture.swapped, first, second))
			if result.Format != "Mach-O universal" || result.Architecture != "CpuAmd64 / CpuArm64" ||
				len(result.Images) != 2 || result.SectionCount != 2 || len(result.Sections) != 2 || len(result.Symbols) != 2 {
				t.Fatalf("informe: %+v", result)
			}
			wantImages := []BinaryImage{{"CpuAmd64", "0x3", FileRange{"0x1000", 0x200}}, {"CpuArm64", "0x0", FileRange{"0x3000", 0x200}}}
			if !slices.Equal(result.Images, wantImages) {
				t.Fatalf("imágenes: %+v", result.Images)
			}
			for index, offset := range []string{"0x1108", "0x3108"} {
				if got := result.Symbols[index]; got.Image != index+1 || got.Name != "sample_entry" || got.Address != "0x1008" ||
					got.Offset != offset || got.Section != "__TEXT/__text" || got.Kind != "Externo" {
					t.Errorf("símbolo: %+v", got)
				}
				section := result.Sections[index]
				if section.Image != index+1 || section.File == nil || section.File.Offset != []string{"0x1100", "0x3100"}[index] {
					t.Errorf("sección: %+v", section)
				}
			}
			for _, offset := range []string{"0x1151", "0x3151"} {
				if !slices.Contains(result.Strings, TextHit{Offset: offset, Text: "sample_entry"}) {
					t.Errorf("cadena ausente en %s: %+v", offset, result.Strings)
				}
			}
		})
	}
	if result := Inspect(first); result.Format != "Mach-O" || len(result.Images) != 0 || len(result.Symbols) != 1 ||
		result.Symbols[0].Offset != "0x108" || result.Symbols[0].Image != 0 {
		t.Fatalf("Mach-O simple: %+v", result)
	}
}

func TestMachOFatReservesStringCapacityForBothImages(t *testing.T) {
	first := thinMachOFixture(t, macho.CpuAmd64, 3, 0x100)
	second := thinMachOFixture(t, macho.CpuArm64, 0, 0x100)
	for range maxBinaryStrings {
		first = append(first, []byte("first image text\x00")...)
	}
	report := Inspect(fatMachOFixture(t, false, false, first, second))
	if !slices.Contains(report.Strings, TextHit{Offset: "0x3151", Text: "sample_entry"}) || len(report.Strings) > maxBinaryStrings {
		t.Fatalf("cadenas: %d, segunda imagen sin su referencia esperada", len(report.Strings))
	}
}

func TestMachOFatRejectsCrossImageBackingAndOverlaps(t *testing.T) {
	first := thinMachOFixture(t, macho.CpuAmd64, 3, 0x2100)
	second := thinMachOFixture(t, macho.CpuArm64, 0, 0x100)
	data := fatMachOFixture(t, false, false, first, second)
	result := Inspect(data)
	if len(result.Sections) != 2 || result.Sections[0].File != nil || len(result.Symbols) != 2 ||
		result.Symbols[0].Offset != "" || result.Symbols[1].Offset != "0x3108" {
		t.Fatalf("respaldo cruzado: %+v", result)
	}
	binary.BigEndian.PutUint32(data[8+20+8:], 0x1080)
	if result := Inspect(data); result.Format != "Sin identificar" || len(result.Images) != 0 {
		t.Fatalf("intervalos superpuestos: %+v", result)
	}
	data = fatMachOFixture(t, true, false, first, second)
	binary.BigEndian.PutUint64(data[8+32+8:], ^uint64(0)-3)
	if result := Inspect(data); result.Format != "Sin identificar" {
		t.Fatalf("desplazamiento fuera de rango: %+v", result)
	}
}

func TestMachOFatKeepsOtherImageWhenHeaderDisagrees(t *testing.T) {
	first := thinMachOFixture(t, macho.CpuAmd64, 3, 0x100)
	second := thinMachOFixture(t, macho.CpuArm64, 0, 0x100)
	data := fatMachOFixture(t, false, false, first, second)
	binary.BigEndian.PutUint32(data[12:], 5)
	result := Inspect(data)
	if len(result.Images) != 1 || result.UnreadableImages != 1 || len(result.Symbols) != 1 ||
		result.Symbols[0].Image != 1 || result.Symbols[0].Offset != "0x3108" {
		t.Fatalf("imagen legible: %+v", result)
	}
}
