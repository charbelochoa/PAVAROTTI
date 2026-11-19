package triaje

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"math"
	"strconv"

	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"
)

const (
	maxBinaryInstructions  = 2048
	maxSectionInstructions = 256
)

type Instruction struct {
	Section int    `json:"section"`
	Address string `json:"address"`
	Offset  string `json:"offset"`
	Bytes   string `json:"bytes"`
	Text    string `json:"text"`
	Target  string `json:"target,omitempty"`
}

type instructionDecoder func(data []byte, address uint64) (int, string, string)

func (b *Binary) addInstructions(data []byte, image binaryImageRange, section int, address, offset, size uint64, decode instructionDecoder, linked bool, budget int) {
	if section < 0 || len(b.Instructions) >= budget {
		b.InstructionsLimited = true
		return
	}
	if b.Sections[section].File == nil || size-1 > math.MaxUint64-address {
		return
	}
	start := image.offset + offset
	limit := min(budget-len(b.Instructions), maxSectionInstructions)
	var limited bool
	b.Instructions, limited = appendInstructions(b.Instructions, data[start:start+size], section, address, start, decode, linked, limit)
	b.InstructionsLimited = b.InstructionsLimited || limited
}

func appendInstructions(rows []Instruction, code []byte, section int, address, start uint64, decode instructionDecoder, linked bool, count int) ([]Instruction, bool) {
	limit := len(rows) + count
	position := 0
	for position < len(code) && len(rows) < limit {
		at := address + uint64(position)
		length, text, target := decode(code[position:], at)
		if length <= 0 || length > len(code)-position {
			break
		}
		if !linked {
			target = ""
		}
		end := position + length
		rows = append(rows, Instruction{Section: section, Address: hexAddress(at),
			Offset: hexAddress(start + uint64(position)), Bytes: hex.EncodeToString(code[position:end]), Text: text, Target: target})
		position = end
	}
	return rows, position < len(code)
}

func elfCodeSize(section *elf.Section) uint64 {
	if section.Type == elf.SHT_NOBITS || section.Type == elf.SHT_NULL ||
		section.Flags&elf.SHF_EXECINSTR == 0 || section.Flags&elf.SHF_COMPRESSED != 0 {
		return 0
	}
	return section.FileSize
}

func peCodeSize(section *pe.Section) uint64 {
	if section.Offset == 0 || section.Characteristics&pe.IMAGE_SCN_MEM_EXECUTE == 0 {
		return 0
	}
	size := section.Size
	if section.VirtualSize != 0 {
		size = min(size, section.VirtualSize)
	}
	return uint64(size)
}

func machOCodeSize(section *macho.Section) uint64 {
	const hasInstructions = 0x80000400
	if section.Flags&hasInstructions == 0 {
		return 0
	}
	return machOFileSize(section)
}

func elfInstructionDecoder(file *elf.File) instructionDecoder {
	if file.Data != elf.ELFDATA2LSB {
		return nil
	}
	switch file.Machine {
	case elf.EM_386:
		return x86InstructionDecoder(32)
	case elf.EM_X86_64:
		return x86InstructionDecoder(64)
	case elf.EM_AARCH64:
		return decodeARM64
	default:
		return nil
	}
}

func peInstructionDecoder(machine uint16) instructionDecoder {
	switch machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		return x86InstructionDecoder(32)
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return x86InstructionDecoder(64)
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return decodeARM64
	default:
		return nil
	}
}

func machOInstructionDecoder(file *macho.File) instructionDecoder {
	if file.ByteOrder != binary.LittleEndian {
		return nil
	}
	switch file.Cpu {
	case macho.Cpu386:
		return x86InstructionDecoder(32)
	case macho.CpuAmd64:
		return x86InstructionDecoder(64)
	case macho.CpuArm64:
		return decodeARM64
	default:
		return nil
	}
}

func x86InstructionDecoder(mode int) instructionDecoder {
	return func(data []byte, address uint64) (int, string, string) {
		inst, err := x86asm.Decode(data, mode)
		if err != nil || inst.Op == 0 {
			return 0, "", ""
		}
		var target string
		for _, arg := range inst.Args {
			if rel, ok := arg.(x86asm.Rel); ok {
				target = relativeTarget(address, int64(inst.Len)+int64(rel))
				break
			}
		}
		return inst.Len, x86asm.IntelSyntax(inst, address, nil), target
	}
}

func decodeARM64(data []byte, address uint64) (int, string, string) {
	const width = 4
	if len(data) < width || address%width != 0 {
		return 0, "", ""
	}
	inst, err := arm64asm.Decode(data)
	if err != nil {
		return width, "", ""
	}
	var target string
	switch inst.Op {
	case arm64asm.B, arm64asm.BL, arm64asm.CBZ, arm64asm.CBNZ, arm64asm.TBZ, arm64asm.TBNZ:
		for _, arg := range inst.Args {
			if rel, ok := arg.(arm64asm.PCRel); ok {
				target = relativeTarget(address, int64(rel))
				break
			}
		}
	}
	return width, arm64asm.GNUSyntax(inst), target
}

func relativeTarget(address uint64, delta int64) string {
	if delta < 0 && uint64(-delta) > address || delta >= 0 && uint64(delta) > math.MaxUint64-address {
		return ""
	}
	return hexAddress(address + uint64(delta))
}

func hexAddress(address uint64) string {
	return "0x" + strconv.FormatUint(address, 16)
}
