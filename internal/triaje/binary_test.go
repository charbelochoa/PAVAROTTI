package triaje

import (
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
}
