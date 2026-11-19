package triaje

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"errors"
	"math"
	"strconv"
	"strings"
)

const MaxBinaryBytes = 32 << 20
const maxWindowInstructions = 64

var ErrInstructionLocation = errors.New("la ubicación no corresponde a una sección ejecutable con bytes decodificables")

type InstructionWindow struct {
	Image        int           `json:"image"`
	Architecture string        `json:"architecture"`
	Section      string        `json:"section"`
	Instructions []Instruction `json:"instructions"`
	Limited      bool          `json:"limited"`
}

type codeSpan struct {
	name                       string
	address, offset, size, raw uint64
}

type codeEntry struct {
	position uint64
	physical bool
}

type codeImage struct {
	file         binaryImageRange
	architecture string
	decode       instructionDecoder
	linked       bool
	entry        *codeEntry
	spans        []codeSpan
}

func OpenInstructionWindow(data []byte, imageIndex int, symbol *Symbol) (InstructionWindow, error) {
	if len(data) == 0 || len(data) > MaxBinaryBytes || imageIndex < 0 || (symbol != nil && symbol.Image != imageIndex) {
		return InstructionWindow{}, ErrInstructionLocation
	}
	image := binaryCodeImage(data, imageIndex)
	if image.decode == nil || (symbol == nil && image.entry == nil) {
		return InstructionWindow{}, ErrInstructionLocation
	}
	span, delta, ok := image.findSpan(symbol)
	if !ok {
		return InstructionWindow{}, ErrInstructionLocation
	}
	position := image.file.offset + span.offset + delta
	end := image.file.offset + span.offset + span.size
	rows, limited := appendInstructions(make([]Instruction, 0, maxWindowInstructions), data[position:end], 0,
		span.address+delta, position, image.decode, image.linked, maxWindowInstructions)
	if len(rows) == 0 {
		return InstructionWindow{}, ErrInstructionLocation
	}
	return InstructionWindow{Image: imageIndex, Architecture: image.architecture, Section: span.name, Instructions: rows, Limited: limited}, nil
}

func (image codeImage) findSpan(symbol *Symbol) (codeSpan, uint64, bool) {
	var anchor, physical uint64
	var physicalEntry bool
	if symbol == nil {
		anchor, physicalEntry = image.entry.position, image.entry.physical
	} else {
		var validAddress, validOffset bool
		anchor, validAddress = ParseBinaryHex(symbol.Address)
		physical, validOffset = ParseBinaryHex(symbol.Offset)
		if !validAddress || !validOffset || symbol.Forwarder != "" {
			return codeSpan{}, 0, false
		}
	}
	var chosen codeSpan
	var delta uint64
	for _, span := range image.spans {
		if span.size == 0 || span.size-1 > math.MaxUint64-span.address || image.file.fileOffset(span.offset, span.raw, 0) == "" {
			continue
		}
		base := span.address
		if physicalEntry {
			base = span.offset
		}
		if anchor < base || anchor-base >= span.size {
			continue
		}
		at := anchor - base
		if symbol != nil && ((symbol.Section != "" && symbol.Section != span.name) || physical != image.file.offset+span.offset+at) {
			continue
		}
		if chosen.size != 0 {
			return codeSpan{}, 0, false
		}
		chosen, delta = span, at
	}
	return chosen, delta, chosen.size != 0
}

func binaryCodeImage(data []byte, index int) codeImage {
	if index > 0 {
		members := usableMachOSlices(data, machOFatSlices(data))
		if index > len(members) {
			return codeImage{}
		}
		member := members[index-1]
		return machOCodeImage(member.file, member.header.binaryImageRange)
	}
	file := binaryImageRange{size: uint64(len(data))}
	reader := bytes.NewReader(data)
	switch {
	case bytes.HasPrefix(data, []byte{0x7f, 'E', 'L', 'F'}):
		parsed, err := elf.NewFile(reader)
		if err == nil {
			return elfCodeImage(parsed, file)
		}
	case bytes.HasPrefix(data, []byte("MZ")):
		parsed, err := pe.NewFile(reader)
		if err == nil {
			return peCodeImage(parsed, file)
		}
	default:
		parsed, err := macho.NewFile(reader)
		if err == nil {
			return machOCodeImage(parsed, file)
		}
	}
	return codeImage{}
}

func elfCodeImage(file *elf.File, source binaryImageRange) codeImage {
	image := codeImage{file: source, architecture: file.Machine.String(), decode: elfInstructionDecoder(file), linked: file.Type != elf.ET_REL}
	if (file.Type == elf.ET_EXEC || file.Type == elf.ET_DYN) && file.Entry != 0 {
		image.entry = &codeEntry{position: file.Entry}
	}
	for _, section := range file.Sections {
		if size := elfCodeSize(section); size != 0 {
			image.spans = append(image.spans, codeSpan{section.Name, section.Addr, section.Offset, size, size})
		}
	}
	return image
}

func peCodeImage(file *pe.File, source binaryImageRange) codeImage {
	image := codeImage{file: source, architecture: peArchitecture(file.Machine), decode: peInstructionDecoder(file.Machine), linked: true}
	var entry uint32
	switch header := file.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		entry = header.AddressOfEntryPoint
	case *pe.OptionalHeader64:
		entry = header.AddressOfEntryPoint
	}
	if entry != 0 {
		image.entry = &codeEntry{position: uint64(entry)}
	}
	for _, section := range file.Sections {
		if size := peCodeSize(section); size != 0 {
			image.spans = append(image.spans, codeSpan{section.Name, uint64(section.VirtualAddress), uint64(section.Offset), size, uint64(section.Size)})
		}
	}
	return image
}

func machOCodeImage(file *macho.File, source binaryImageRange) codeImage {
	image := codeImage{file: source, architecture: file.Cpu.String(), decode: machOInstructionDecoder(file), linked: file.Type != macho.TypeObj}
	image.entry = machOCodeEntry(file)
	for _, section := range file.Sections {
		if size := machOCodeSize(section); size != 0 {
			image.spans = append(image.spans, codeSpan{section.Seg + "/" + section.Name, section.Addr, uint64(section.Offset), size, size})
		}
	}
	return image
}

func machOCodeEntry(file *macho.File) *codeEntry {
	if file.Type != macho.TypeExec {
		return nil
	}
	const entryPointCommand = 0x80000028
	text := file.Segment("__TEXT")
	if text == nil {
		return nil
	}
	var found *codeEntry
	for _, load := range file.Loads {
		raw := load.Raw()
		if len(raw) < 8 || file.ByteOrder.Uint32(raw) != entryPointCommand {
			continue
		}
		if len(raw) != 24 || found != nil {
			return nil
		}
		offset := file.ByteOrder.Uint64(raw[8:])
		if offset >= text.Filesz || offset > math.MaxUint64-text.Offset {
			return nil
		}
		found = &codeEntry{position: text.Offset + offset, physical: true}
	}
	return found
}

func ParseBinaryHex(value string) (uint64, bool) {
	digits, ok := strings.CutPrefix(value, "0x")
	if !ok {
		return 0, false
	}
	position, err := strconv.ParseUint(digits, 16, 64)
	return position, err == nil
}
