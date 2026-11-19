package triaje

import (
	"debug/elf"
	"encoding/binary"
	"testing"
)

func TestInspectPEFileRanges(t *testing.T) {
	data := make([]byte, 0x300)
	copy(data, "MZ")
	binary.LittleEndian.PutUint32(data[0x3c:], 0x80)
	copy(data[0x80:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(data[0x84:], 0x8664)
	binary.LittleEndian.PutUint16(data[0x86:], 3)
	binary.LittleEndian.PutUint32(data[0x8c:], 0x290)
	binary.LittleEndian.PutUint32(data[0x90:], 2)
	for index, item := range []struct {
		name    string
		offset  uint32
		backing uint32
	}{
		{".text", 0x200, 0x80},
		{".bss", 0, 0},
		{".bad", 0x280, 0x100},
	} {
		header := data[0x98+index*40:]
		copy(header, item.name)
		binary.LittleEndian.PutUint32(header[8:], 0x400)
		binary.LittleEndian.PutUint32(header[12:], uint32((index+1)*0x1000))
		binary.LittleEndian.PutUint32(header[16:], item.backing)
		binary.LittleEndian.PutUint32(header[20:], item.offset)
	}
	copy(data[0x218:], "Observed fixture string")
	for index, symbol := range []struct {
		name    string
		value   uint32
		section uint16
	}{{"fixture", 0x18, 1}, {"membss", 0, 2}} {
		entry := data[0x290+index*18:]
		copy(entry, symbol.name)
		binary.LittleEndian.PutUint32(entry[8:], symbol.value)
		binary.LittleEndian.PutUint16(entry[12:], symbol.section)
		binary.LittleEndian.PutUint16(entry[14:], 0x20)
		entry[16] = 2
	}
	binary.LittleEndian.PutUint32(data[0x290+36:], 4)
	report := Inspect(data)
	if report.Format != "PE" || report.Architecture != "x86-64" || report.SectionCount != 3 || len(report.Sections) != 3 {
		t.Fatalf("cabeceras: %+v", report)
	}
	section := report.Sections[0]
	if section.Name != ".text" || section.Address != "0x1000" || section.Size != 0x400 || section.File == nil ||
		section.File.Offset != "0x200" || section.File.Size != 0x80 {
		t.Fatalf("intervalo físico: %+v", section)
	}
	if report.Sections[1].File != nil || report.Sections[2].File != nil {
		t.Fatal("se guardó un intervalo sin respaldo completo en el archivo")
	}
	if len(report.Strings) != 1 || report.Strings[0] != (TextHit{"0x218", "Observed fixture string"}) {
		t.Fatalf("desplazamiento de cadenas: %+v", report.Strings)
	}
	if len(report.Symbols) != 2 || report.Symbols[0] != (Symbol{
		Name: "fixture", Kind: "Función COFF", Address: "0x1018", Section: ".text", Offset: "0x218",
	}) || report.Symbols[1].Offset != "" {
		t.Fatalf("símbolos: %+v", report.Symbols)
	}
}

func TestELFRelocatableSymbolsRespectPhysicalBacking(t *testing.T) {
	file := &elf.File{
		FileHeader: elf.FileHeader{Class: elf.ELFCLASS32, Type: elf.ET_REL, Machine: elf.EM_ARM, ByteOrder: binary.LittleEndian},
		Sections: []*elf.Section{{}, {SectionHeader: elf.SectionHeader{
			Name: ".text", Type: elf.SHT_PROGBITS, Offset: 0x30, FileSize: 0x10,
		}}, {SectionHeader: elf.SectionHeader{
			Name: ".symtab", Type: elf.SHT_SYMTAB, Offset: 0x40, FileSize: 3 * elf.Sym32Size, Link: 3,
		}}, {SectionHeader: elf.SectionHeader{
			Name: ".strtab", Type: elf.SHT_STRTAB, Offset: 0x70, FileSize: 7,
		}}},
	}
	data := make([]byte, 0x80)
	copy(data[0x70:], "\x00thumb\x00")
	for _, entryAt := range []int{0x50, 0x60} {
		entry := data[entryAt:]
		binary.LittleEndian.PutUint32(entry, 1)
		binary.LittleEndian.PutUint32(entry[4:], 5)
		entry[12] = byte(elf.STT_FUNC)
	}
	binary.LittleEndian.PutUint16(data[0x50+14:], 1)
	report := Binary{Size: len(data)}
	report.elfSymbols(file, data)
	if len(report.Symbols) != 1 || report.Symbols[0] != (Symbol{
		Name: "thumb", Kind: "STT_FUNC", Address: "0x5", Section: ".text", Offset: "0x34",
	}) {
		t.Fatalf("símbolo Thumb: %+v", report.Symbols)
	}
	file.Sections[1].Type = elf.SHT_NOBITS
	report.Symbols = nil
	report.elfSymbols(file, data)
	if len(report.Symbols) != 1 || report.Symbols[0].Offset != "" {
		t.Fatalf("símbolo sin bytes de respaldo: %+v", report.Symbols)
	}
}
