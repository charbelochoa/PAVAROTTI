package triaje

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"errors"
	"testing"
)

func TestInstructionWindowBeyondStoredELFListing(t *testing.T) {
	code := append(bytes.Repeat([]byte{0x90}, 300), 0xeb, 1, 0x90, 0xc3)
	data := elfInstructionFixture(t, elf.ET_EXEC, code)
	binary.LittleEndian.PutUint64(data[24:], 0x40112c)
	report := Inspect(data)
	if len(report.Instructions) != 256 || !report.InstructionsLimited {
		t.Fatalf("listado inicial: %d, %v", len(report.Instructions), report.InstructionsLimited)
	}
	for _, symbol := range []*Symbol{nil, {Address: "0x40112c", Offset: "0x22c"}} {
		window, err := OpenInstructionWindow(data, 0, symbol)
		if err != nil || window.Limited || len(window.Instructions) != 3 || window.Instructions[0].Bytes != "eb01" ||
			window.Instructions[0].Target != "0x40112f" || window.Instructions[2].Offset != "0x22f" {
			t.Fatalf("ventana ELF: %+v, %v", window, err)
		}
	}
	for _, bad := range []Symbol{
		{Address: "0x402000", Offset: "0x280"},
		{Address: "0x40112c", Offset: "0x22d"},
		{Address: "0x40112c", Offset: "0x22c", Image: 1},
	} {
		if _, err := OpenInstructionWindow(data, 0, &bad); !errors.Is(err, ErrInstructionLocation) {
			t.Fatalf("ubicación aceptada: %+v, %v", bad, err)
		}
	}
	binary.LittleEndian.PutUint64(data[24:], 0x401000)
	window, err := OpenInstructionWindow(data, 0, nil)
	if err != nil || !window.Limited || len(window.Instructions) != maxWindowInstructions {
		t.Fatalf("límite de ventana: %+v, %v", window, err)
	}
}

func TestInstructionWindowPEUsesExecutableVirtualExtent(t *testing.T) {
	for _, machine := range []uint16{pe.IMAGE_FILE_MACHINE_I386, pe.IMAGE_FILE_MACHINE_AMD64} {
		data := peExportFixture(t, machine)
		order := binary.LittleEndian
		header := 0x98 + int(order.Uint16(data[0x94:]))
		order.PutUint32(data[0x98+16:], 0x1010)
		order.PutUint32(data[header+8:], 0x13)
		order.PutUint32(data[header+36:], pe.IMAGE_SCN_MEM_EXECUTE)
		copy(data[0x210:], []byte{0x90, 0x90, 0xc3})
		window, err := OpenInstructionWindow(data, 0, nil)
		if err != nil || window.Section != ".text" || len(window.Instructions) != 3 || window.Instructions[0].Address != "0x1010" ||
			window.Instructions[0].Offset != "0x210" || window.Instructions[2].Text != "ret" {
			t.Fatalf("punto de entrada PE: %+v, %v", window, err)
		}
		order.PutUint32(data[0x98+16:], 0x1020)
		if _, err := OpenInstructionWindow(data, 0, nil); !errors.Is(err, ErrInstructionLocation) {
			t.Fatalf("se abrió relleno fuera del tamaño virtual: %v", err)
		}
	}
}

func TestInstructionWindowMachOResolvesEntryInsideSelectedImage(t *testing.T) {
	first, second := thinMachOFixture(t, macho.CpuAmd64, 3, 0x110), thinMachOFixture(t, macho.CpuArm64, 0, 0x110)
	for _, image := range [][]byte{first, second} {
		order := binary.LittleEndian
		order.PutUint32(image[32+72+64:], 0x80000000)
		order.PutUint32(image[16:], 3)
		commands := order.Uint32(image[20:])
		order.PutUint32(image[20:], commands+24)
		entry := image[32+commands:]
		order.PutUint32(entry, 0x80000028)
		order.PutUint32(entry[4:], 24)
		order.PutUint64(entry[8:], 0x118)
	}
	first[0x118] = 0xc3
	copy(second[0x118:], []byte{0xc0, 0x03, 0x5f, 0xd6})
	data := fatMachOFixture(t, true, false, first, second)
	for index, offset := range []string{"0x1118", "0x3118"} {
		window, err := OpenInstructionWindow(data, index+1, nil)
		if err != nil || len(window.Instructions) == 0 || window.Image != index+1 || window.Section != "__TEXT/__text" ||
			window.Instructions[0].Address != "0x1008" || window.Instructions[0].Offset != offset || window.Instructions[0].Text != "ret" {
			t.Fatalf("punto de entrada Mach-O: %+v, %v", window, err)
		}
	}
}
