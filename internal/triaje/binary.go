package triaje

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
)

type Binary struct {
	SHA256              string        `json:"sha256"`
	Format              string        `json:"format"`
	Architecture        string        `json:"architecture,omitempty"`
	Size                int           `json:"size"`
	Sections            []Section     `json:"sections"`
	SectionCount        int           `json:"section_count,omitempty"`
	Strings             []TextHit     `json:"strings,omitempty"`
	Symbols             []Symbol      `json:"symbols,omitempty"`
	SymbolsLimited      bool          `json:"symbols_limited,omitempty"`
	Images              []BinaryImage `json:"images,omitempty"`
	UnreadableImages    int           `json:"unreadable_images,omitempty"`
	Instructions        []Instruction `json:"instructions,omitempty"`
	InstructionsLimited bool          `json:"instructions_limited,omitempty"`
}

const (
	maxBinarySections = 256
	maxBinaryStrings  = 128
)

type BinaryImage struct {
	Architecture string    `json:"architecture"`
	Subtype      string    `json:"subtype"`
	File         FileRange `json:"file"`
}

type Section struct {
	Name    string     `json:"name"`
	Address string     `json:"address"`
	Size    uint64     `json:"size"`
	File    *FileRange `json:"file,omitempty"`
	Image   int        `json:"image,omitempty"`
}

type FileRange struct {
	Offset string `json:"offset"`
	Size   uint64 `json:"size"`
}

type TextHit struct {
	Offset string `json:"offset"`
	Text   string `json:"text"`
}

type binaryImageRange struct {
	index        int
	offset, size uint64
}

func Inspect(data []byte) Binary {
	result := Binary{SHA256: fmt.Sprintf("%x", sha256.Sum256(data)), Format: "Sin identificar", Size: len(data)}
	reader := bytes.NewReader(data)
	image := binaryImageRange{size: uint64(len(data))}
	switch {
	case bytes.HasPrefix(data, []byte{0x7f, 'E', 'L', 'F'}):
		if file, err := elf.NewFile(reader); err == nil {
			result.Format, result.Architecture = "ELF", file.Machine.String()
			decode := elfInstructionDecoder(file)
			for _, section := range file.Sections {
				size := section.FileSize
				if section.Type == elf.SHT_NOBITS || section.Type == elf.SHT_NULL {
					size = 0
				}
				index := result.add(image, section.Name, section.Addr, section.Size, section.Offset, size)
				if decode != nil && section.Flags&elf.SHF_EXECINSTR != 0 && section.Flags&elf.SHF_COMPRESSED == 0 && size > 0 {
					result.addInstructions(data, image, index, section.Addr, section.Offset, size, decode, file.Type != elf.ET_REL, maxBinaryInstructions)
				}
			}
			result.elfSymbols(file, data)
		}
	case bytes.HasPrefix(data, []byte("MZ")):
		if file, err := pe.NewFile(reader); err == nil {
			bits := map[uint16]string{pe.IMAGE_FILE_MACHINE_AMD64: "x86-64", pe.IMAGE_FILE_MACHINE_I386: "x86", pe.IMAGE_FILE_MACHINE_ARM64: "ARM64"}
			result.Format, result.Architecture = "PE", bits[file.Machine]
			decode := peInstructionDecoder(file.Machine)
			for _, section := range file.Sections {
				size := section.Size
				if section.Offset == 0 {
					size = 0
				}
				index := result.add(image, section.Name, uint64(section.VirtualAddress), uint64(section.VirtualSize), uint64(section.Offset), uint64(size))
				if decode != nil && section.Characteristics&pe.IMAGE_SCN_MEM_EXECUTE != 0 && size > 0 {
					if section.VirtualSize != 0 {
						size = min(size, section.VirtualSize)
					}
					result.addInstructions(data, image, index, uint64(section.VirtualAddress), uint64(section.Offset), uint64(size), decode, true, maxBinaryInstructions)
				}
			}
			result.peExports(file, data)
			result.peSymbols(file)
		}
	default:
		if file, err := macho.NewFile(reader); err == nil {
			result.Format, result.Architecture = "Mach-O", file.Cpu.String()
			result.inspectMachO(data, file, image, 1)
		} else {
			result.inspectMachOFat(data)
		}
	}
	if len(result.Images) == 0 {
		result.Strings = printableStrings(data, 0, maxBinaryStrings)
	}
	return result
}

func printableStrings(data []byte, base uint64, limit int) []TextHit {
	const minimum = 8
	const preview = 160
	var hits []TextHit
	for offset := 0; offset < len(data) && len(hits) < limit; {
		if !ascii(data[offset]) {
			offset++
			continue
		}
		start := offset
		for offset < len(data) && ascii(data[offset]) {
			offset++
		}
		if offset-start >= minimum {
			hits = append(hits, TextHit{Offset: fmt.Sprintf("0x%x", base+uint64(start)),
				Text: string(data[start:min(offset, start+preview)])})
		}
	}
	return hits
}

func ascii(value byte) bool {
	return value >= ' ' && value <= '~' || value == '\r' || value == '\n' || value == '\t'
}

func (b *Binary) add(image binaryImageRange, name string, address, size, offset, fileSize uint64) int {
	b.SectionCount++
	if len(b.Sections) == maxBinarySections {
		return -1
	}
	section := Section{Name: name, Address: fmt.Sprintf("0x%x", address), Size: size, Image: image.index}
	if physical := image.fileOffset(offset, fileSize, 0); physical != "" {
		section.File = &FileRange{Offset: physical, Size: fileSize}
	}
	b.Sections = append(b.Sections, section)
	return len(b.Sections) - 1
}

func (b *Binary) fileOffset(offset, size, delta uint64) string {
	return (binaryImageRange{size: uint64(b.Size)}).fileOffset(offset, size, delta)
}

func (image binaryImageRange) fileOffset(offset, size, delta uint64) string {
	if offset >= image.size || size > image.size-offset || delta >= size {
		return ""
	}
	return fmt.Sprintf("0x%x", image.offset+offset+delta)
}
