package triaje

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"testing"
)

func peExportFixture(t *testing.T, machine uint16) []byte {
	t.Helper()
	order := binary.LittleEndian
	data := make([]byte, 0x400)
	copy(data, "MZ")
	order.PutUint32(data[0x3c:], 0x80)
	copy(data[0x80:], "PE\x00\x00")
	order.PutUint16(data[0x84:], machine)
	order.PutUint16(data[0x86:], 3)
	directories := [16]pe.DataDirectory{{VirtualAddress: 0x2000, Size: 0x100}}
	var optional any = pe.OptionalHeader64{Magic: 0x20b, NumberOfRvaAndSizes: 16, SizeOfHeaders: 0x200, DataDirectory: directories}
	if machine == pe.IMAGE_FILE_MACHINE_I386 {
		optional = pe.OptionalHeader32{Magic: 0x10b, NumberOfRvaAndSizes: 16, SizeOfHeaders: 0x200, DataDirectory: directories}
	}
	order.PutUint16(data[0x94:], uint16(binary.Size(optional)))
	header := bytes.NewBuffer(data[0x98:0x98])
	if err := binary.Write(header, order, optional); err != nil {
		t.Fatal(err)
	}
	for index, section := range []struct {
		name         string
		offset, size uint32
		virtualSize  uint32
	}{{".text", 0x200, 0x80, 0x80}, {".edata", 0x300, 0x100, 0x100}, {".bss", 0, 0, 0x80}} {
		entry := data[0x98+binary.Size(optional)+index*40:]
		copy(entry, section.name)
		order.PutUint32(entry[8:], section.virtualSize)
		order.PutUint32(entry[12:], uint32(index+1)*0x1000)
		order.PutUint32(entry[16:], section.size)
		order.PutUint32(entry[20:], section.offset)
	}
	for index, value := range []uint32{7, 5, 4, 0x2030, 0x2050, 0x2060} {
		order.PutUint32(data[0x310+index*4:], value)
	}
	for index, rva := range []uint32{0x1010, 0x20c0, 0x1020, 0x3010, 0} {
		order.PutUint32(data[0x330+index*4:], rva)
	}
	for index, name := range []string{"ObservedAlias", "ObservedEntry", "ForwardedEntry", "MemoryEntry"} {
		offset := 0x370 + index*16
		copy(data[offset:], name)
		order.PutUint32(data[0x350+index*4:], 0x2000+uint32(offset-0x300))
		order.PutUint16(data[0x360+index*2:], []uint16{0, 0, 1, 3}[index])
	}
	copy(data[0x3c0:], "PEER.Target")
	return data
}

func TestPEExportsResolveAliasesAndPhysicalLocations(t *testing.T) {
	for _, fixture := range []struct {
		name    string
		machine uint16
	}{{"PE32", pe.IMAGE_FILE_MACHINE_I386}, {"PE32+", pe.IMAGE_FILE_MACHINE_AMD64}} {
		t.Run(fixture.name, func(t *testing.T) {
			result := Inspect(peExportFixture(t, fixture.machine))
			if result.Format != "PE" || result.SymbolsLimited || len(result.Symbols) != 5 {
				t.Fatalf("informe: %+v", result)
			}
			for index, want := range []struct {
				name, address, section, offset, forwarder string
				ordinal                                   uint32
			}{
				{"ObservedAlias", "0x1010", ".text", "0x210", "", 7},
				{"ObservedEntry", "0x1010", ".text", "0x210", "", 7},
				{"ForwardedEntry", "0x20c0", "", "", "PEER.Target", 8},
				{"MemoryEntry", "0x3010", ".bss", "", "", 10},
				{"Ordinal 9", "0x1020", ".text", "0x220", "", 9},
			} {
				got := result.Symbols[index]
				if got.Name != want.name || got.Address != want.address || got.Section != want.section || got.Offset != want.offset ||
					got.Forwarder != want.forwarder || got.Ordinal == nil || *got.Ordinal != want.ordinal || got.Kind != "Exportación PE" {
					t.Errorf("símbolo %d: %+v", index, got)
				}
			}
		})
	}
}

func TestPEExportsRejectUnbackedTablesAndUnterminatedForwarders(t *testing.T) {
	data := peExportFixture(t, pe.IMAGE_FILE_MACHINE_AMD64)
	binary.LittleEndian.PutUint32(data[0x320:], 0x20ff)
	if got := Inspect(data); got.Format != "PE" || len(got.Symbols) != 0 {
		t.Fatalf("tabla fuera del archivo: %+v", got.Symbols)
	}
	data = peExportFixture(t, pe.IMAGE_FILE_MACHINE_AMD64)
	for index := 0x3c0; index < len(data); index++ {
		data[index] = 'A'
	}
	got := Inspect(data)
	if len(got.Symbols) != 4 || got.Symbols[2].Name != "MemoryEntry" {
		t.Fatalf("nombre reenviado sin terminador: %+v", got.Symbols)
	}
}
