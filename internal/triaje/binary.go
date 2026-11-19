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
	SHA256       string    `json:"sha256"`
	Format       string    `json:"format"`
	Architecture string    `json:"architecture,omitempty"`
	Size         int       `json:"size"`
	Sections     []Section `json:"sections"`
	SectionCount int       `json:"section_count,omitempty"`
	Strings      []TextHit `json:"strings,omitempty"`
}

type Section struct {
	Name    string     `json:"name"`
	Address string     `json:"address"`
	Size    uint64     `json:"size"`
	File    *FileRange `json:"file,omitempty"`
}

type FileRange struct {
	Offset string `json:"offset"`
	Size   uint64 `json:"size"`
}

type TextHit struct {
	Offset string `json:"offset"`
	Text   string `json:"text"`
}

func Inspect(data []byte) Binary {
	result := Binary{SHA256: fmt.Sprintf("%x", sha256.Sum256(data)), Format: "Sin identificar", Size: len(data)}
	reader := bytes.NewReader(data)
	switch {
	case bytes.HasPrefix(data, []byte{0x7f, 'E', 'L', 'F'}):
		if file, err := elf.NewFile(reader); err == nil {
			result.Format, result.Architecture = "ELF", file.Machine.String()
			for _, section := range file.Sections {
				size := section.FileSize
				if section.Type == elf.SHT_NOBITS || section.Type == elf.SHT_NULL {
					size = 0
				}
				result.add(section.Name, section.Addr, section.Size, section.Offset, size)
			}
		}
	case bytes.HasPrefix(data, []byte("MZ")):
		if file, err := pe.NewFile(reader); err == nil {
			bits := map[uint16]string{pe.IMAGE_FILE_MACHINE_AMD64: "x86-64", pe.IMAGE_FILE_MACHINE_I386: "x86", pe.IMAGE_FILE_MACHINE_ARM64: "ARM64"}
			result.Format, result.Architecture = "PE", bits[file.Machine]
			for _, section := range file.Sections {
				size := section.Size
				if section.Offset == 0 {
					size = 0
				}
				result.add(section.Name, uint64(section.VirtualAddress), uint64(section.VirtualSize), uint64(section.Offset), uint64(size))
			}
		}
	default:
		if file, err := macho.NewFile(reader); err == nil {
			result.Format, result.Architecture = "Mach-O", file.Cpu.String()
			const (
				sectionTypeMask     = 0xff
				zeroFill            = 0x1
				gbZeroFill          = 0xc
				threadLocalZeroFill = 0x12
			)
			for _, section := range file.Sections {
				size := section.Size
				switch section.Flags & sectionTypeMask {
				case zeroFill, gbZeroFill, threadLocalZeroFill:
					size = 0
				}
				result.add(section.Seg+"/"+section.Name, section.Addr, section.Size, uint64(section.Offset), size)
			}
		}
	}
	result.Strings = printableStrings(data)
	return result
}

func printableStrings(data []byte) []TextHit {
	const minimum = 8
	const limit = 128
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
			hits = append(hits, TextHit{Offset: fmt.Sprintf("0x%x", start),
				Text: string(data[start:min(offset, start+preview)])})
		}
	}
	return hits
}

func ascii(value byte) bool {
	return value >= ' ' && value <= '~' || value == '\r' || value == '\n' || value == '\t'
}

func (b *Binary) add(name string, address, size, offset, fileSize uint64) {
	const maxSections = 256
	b.SectionCount++
	if len(b.Sections) == maxSections {
		return
	}
	section := Section{Name: name, Address: fmt.Sprintf("0x%x", address), Size: size}
	if fileSize > 0 && offset < uint64(b.Size) && fileSize <= uint64(b.Size)-offset {
		section.File = &FileRange{Offset: fmt.Sprintf("0x%x", offset), Size: fileSize}
	}
	b.Sections = append(b.Sections, section)
}
