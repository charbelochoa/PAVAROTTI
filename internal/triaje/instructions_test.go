package triaje

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"testing"
)

func TestInspectELFInstructionsUseVirtualAndPhysicalAddresses(t *testing.T) {
	code := []byte{0x90, 0xe8, 0x01, 0, 0, 0, 0x90, 0xc3}
	for _, kind := range []elf.Type{elf.ET_EXEC, elf.ET_REL} {
		t.Run(kind.String(), func(t *testing.T) {
			result := Inspect(elfInstructionFixture(t, kind, code))
			if len(result.Instructions) != 4 || result.InstructionsLimited {
				t.Fatalf("listado ELF: %+v", result.Instructions)
			}
			want := Instruction{Section: 1, Address: "0x401001", Offset: "0x101", Bytes: "e801000000", Text: "call 0x401007", Target: "0x401007"}
			if kind == elf.ET_REL {
				want.Address, want.Text, want.Target = "0x1", "call 0x7", ""
			}
			if actual := result.Instructions[1]; actual != want {
				t.Fatalf("instrucción ELF: %+v, esperada %+v", actual, want)
			}
		})
	}
}

func TestInspectPEInstructionsIgnoreRawPaddingAndUseRVA(t *testing.T) {
	for _, kind := range []uint16{pe.IMAGE_FILE_MACHINE_I386, pe.IMAGE_FILE_MACHINE_AMD64} {
		data := peExportFixture(t, kind)
		start := 0x98 + int(binary.LittleEndian.Uint16(data[0x94:]))
		code := []byte{0x90, 0xeb, 0x01, 0x90, 0xc3}
		binary.LittleEndian.PutUint32(data[start+8:], uint32(len(code)))
		binary.LittleEndian.PutUint32(data[start+36:], pe.IMAGE_SCN_MEM_EXECUTE)
		copy(data[0x200:], code)
		result := Inspect(data)
		if len(result.Instructions) != 4 || result.InstructionsLimited || result.Instructions[1] != (Instruction{
			Section: 0, Address: "0x1001", Offset: "0x201", Bytes: "eb01", Text: "jmp 0x1004", Target: "0x1004",
		}) {
			t.Fatalf("listado PE %x: %+v", kind, result.Instructions)
		}
	}
}

func TestUniversalInstructionsResolveOffsetsPerImage(t *testing.T) {
	first, second := thinMachOFixture(t, macho.CpuAmd64, 3, 0x100), thinMachOFixture(t, macho.CpuArm64, 0, 0x100)
	const flags = 32 + 72 + 64
	for _, image := range [][]byte{first, second} {
		binary.LittleEndian.PutUint32(image[flags:], 0x80000000)
	}
	copy(first[0x100:], []byte{0xeb, 0x02, 0x90, 0x90, 0xc3})
	copy(second[0x100:], []byte{2, 0, 0, 0x14, 0x1f, 0x20, 0x03, 0xd5, 0xc0, 0x03, 0x5f, 0xd6, 0xff, 0xff, 0xff, 0xff})
	result := Inspect(fatMachOFixture(t, true, false, first, second))
	if len(result.Instructions) < 5 || len(result.Sections) != 2 ||
		result.Instructions[0] != (Instruction{Section: 0, Address: "0x1000", Offset: "0x1100", Bytes: "eb02", Text: "jmp 0x1004", Target: "0x1004"}) {
		t.Fatalf("instrucciones de las imágenes: %+v", result.Instructions)
	}
	var arm []Instruction
	for _, row := range result.Instructions {
		if result.Sections[row.Section].Image == 2 {
			arm = append(arm, row)
		}
	}
	if len(arm) != 4 || arm[0].Target != "0x1008" || arm[0].Offset != "0x3100" || arm[0].Address != "0x1000" ||
		arm[2].Text != "ret" || arm[3].Text != "" || arm[3].Bytes != "ffffffff" {
		t.Fatalf("listado ARM64: %+v", arm)
	}
}

func TestInspectInstructionsStopAtBudgetAndTruncation(t *testing.T) {
	long := Inspect(elfInstructionFixture(t, elf.ET_EXEC, bytes.Repeat([]byte{0x90}, maxSectionInstructions+1)))
	if len(long.Instructions) != maxSectionInstructions || !long.InstructionsLimited {
		t.Fatalf("límite por sección: %d, %v", len(long.Instructions), long.InstructionsLimited)
	}
	short := Inspect(elfInstructionFixture(t, elf.ET_EXEC, []byte{0x90, 0xe8, 0x01}))
	if len(short.Instructions) != 1 || !short.InstructionsLimited {
		t.Fatalf("instrucción truncada: %+v, %v", short.Instructions, short.InstructionsLimited)
	}
}

func elfInstructionFixture(t *testing.T, kind elf.Type, code []byte) []byte {
	t.Helper()
	sectionStart := 0x300
	sectionSize := binary.Size(elf.Section64{})
	data := make([]byte, sectionStart+3*sectionSize)
	address := uint64(0x401000)
	if kind == elf.ET_REL {
		address = 0
	}
	header := elf.Header64{Type: uint16(kind), Machine: uint16(elf.EM_X86_64), Version: 1, Entry: address, Shoff: uint64(sectionStart),
		Ehsize: uint16(binary.Size(elf.Header64{})), Shentsize: uint16(sectionSize), Shnum: 3}
	copy(header.Ident[:], "\x7fELF\x02\x01\x01")
	if err := binary.Write(bytes.NewBuffer(data[:0]), binary.LittleEndian, header); err != nil {
		t.Fatal(err)
	}
	sections := []elf.Section64{{},
		{Type: uint32(elf.SHT_PROGBITS), Flags: uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), Addr: address, Off: 0x100, Size: uint64(len(code))},
		{Type: uint32(elf.SHT_PROGBITS), Flags: uint64(elf.SHF_ALLOC), Addr: 0x402000, Off: 0x280, Size: 8},
	}
	if err := binary.Write(bytes.NewBuffer(data[sectionStart:sectionStart]), binary.LittleEndian, sections); err != nil {
		t.Fatal(err)
	}
	copy(data[0x100:], code)
	copy(data[0x280:], []byte{0x90, 0xc3})
	return data
}
