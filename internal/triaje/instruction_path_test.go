package triaje

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"errors"
	"testing"
)

func TestInstructionPathReplaysJumpsBeyondEachWindow(t *testing.T) {
	code := bytes.Repeat([]byte{0x90}, 304)
	for _, jump := range []struct{ from, to int }{{0, 128}, {128, 300}} {
		code[jump.from] = 0xe9
		binary.LittleEndian.PutUint32(code[jump.from+1:], uint32(jump.to-jump.from-5))
	}
	code[300] = 0xc3
	data := elfInstructionFixture(t, elf.ET_EXEC, code)
	window, err := OpenInstructionWindow(data, 0, nil, 0, 0)
	if err != nil || window.Origin == nil || window.Origin.Address != "0x401080" || window.Origin.Offset != "0x180" ||
		window.Instructions[0].Address != "0x40112c" || window.Instructions[0].Offset != "0x22c" || window.Instructions[0].Text != "ret" {
		t.Fatalf("recorrido verificado: %+v, %v", window, err)
	}
	for _, invalid := range [][]int{{1}, {64}, {0, 1}, {-1}, make([]int, MaxInstructionSteps+1)} {
		if _, err := OpenInstructionWindow(data, 0, nil, invalid...); !errors.Is(err, ErrInstructionLocation) {
			t.Fatalf("recorrido inválido %v: %v", invalid, err)
		}
	}
}

func TestInstructionPathRequiresUniqueExecutableBacking(t *testing.T) {
	code := []byte{0xe9, 0xfb, 0x0f, 0, 0}
	data := elfInstructionFixture(t, elf.ET_EXEC, code)
	if _, err := OpenInstructionWindow(data, 0, nil, 0); !errors.Is(err, ErrInstructionLocation) {
		t.Fatalf("destino en datos: %v", err)
	}
	order := binary.LittleEndian
	lastHeader := 0x300 + 2*binary.Size(elf.Section64{})
	order.PutUint64(data[lastHeader+8:], uint64(elf.SHF_ALLOC|elf.SHF_EXECINSTR))
	window, err := OpenInstructionWindow(data, 0, nil, 0)
	if err != nil || window.Origin == nil || window.Instructions[0].Address != "0x402000" || window.Instructions[0].Offset != "0x280" {
		t.Fatalf("salto a otra sección ejecutable: %+v, %v", window, err)
	}
	order.PutUint64(data[lastHeader+16:], 0x401000)
	code = []byte{0xe9, 0xfb, 0xff, 0xff, 0xff}
	copy(data[0x100:], code)
	symbol := Symbol{Address: "0x401000", Offset: "0x100"}
	if _, err := OpenInstructionWindow(data, 0, &symbol, 0); !errors.Is(err, ErrInstructionLocation) {
		t.Fatalf("destino con dos respaldos físicos: %v", err)
	}
}

func TestInstructionPathStaysInOriginalMachOImage(t *testing.T) {
	first := thinMachOFixture(t, macho.CpuAmd64, 3, 0x100)
	second := thinMachOFixture(t, macho.CpuArm64, 0, 0x100)
	for _, image := range [][]byte{first, second} {
		binary.LittleEndian.PutUint32(image[32+72+64:], 0x80000000)
	}
	binary.LittleEndian.PutUint64(second[32+72+32:], 0x1020)
	copy(first[0x100:], []byte{0xeb, 0x1e})
	copy(second[0x100:], []byte{0xc0, 0x03, 0x5f, 0xd6})
	data := fatMachOFixture(t, true, false, first, second)
	arm := Symbol{Image: 2, Address: "0x1020", Offset: "0x3100"}
	if window, err := OpenInstructionWindow(data, 2, &arm); err != nil || window.Instructions[0].Text != "ret" {
		t.Fatalf("imagen destino de control: %+v, %v", window, err)
	}
	x86 := Symbol{Image: 1, Address: "0x1000", Offset: "0x1100"}
	if _, err := OpenInstructionWindow(data, 1, &x86, 0); !errors.Is(err, ErrInstructionLocation) {
		t.Fatalf("se siguió el salto a otra imagen: %v", err)
	}
}
