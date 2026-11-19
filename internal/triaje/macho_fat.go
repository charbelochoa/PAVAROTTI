package triaje

import (
	"bytes"
	"cmp"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"slices"
	"strings"
)

const (
	machOFat64      = 0xcafebabf
	machOFatSwapped = 0xbebafeca
	machOFat64Swap  = 0xbfbafeca
	maxMachOImages  = 64
)

type machOArchitecture struct {
	cpu     macho.Cpu
	subtype uint32
}

type machOSlice struct {
	machOArchitecture
	binaryImageRange
}

func (b *Binary) inspectMachO(file *macho.File, image binaryImageRange, remaining int) {
	sectionBudget := min(len(file.Sections), (maxBinarySections-len(b.Sections))/remaining)
	b.SectionCount += len(file.Sections) - sectionBudget
	for _, section := range file.Sections[:sectionBudget] {
		b.add(image, section.Seg+"/"+section.Name, section.Addr, section.Size, uint64(section.Offset), machOFileSize(section))
	}
	b.machOSymbols(file, image, len(b.Symbols)+(maxBinarySymbols-len(b.Symbols))/remaining)
}

func (b *Binary) inspectMachOFat(data []byte) {
	headers := machOFatSlices(data)
	var usable []struct {
		header machOSlice
		file   *macho.File
	}
	var architectures []string
	for _, member := range headers {
		reader := bytes.NewReader(data[member.offset : member.offset+member.size])
		file, err := macho.NewFile(reader)
		if err != nil || file.Cpu != member.cpu || file.SubCpu != member.subtype {
			continue
		}
		usable = append(usable, struct {
			header machOSlice
			file   *macho.File
		}{member, file})
		label := file.Cpu.String()
		if !slices.Contains(architectures, label) {
			architectures = append(architectures, label)
		}
	}
	if len(usable) == 0 {
		return
	}
	b.Format, b.Architecture = "Mach-O universal", strings.Join(architectures, " / ")
	b.UnreadableImages = len(headers) - len(usable)
	for index, member := range usable {
		header := member.header
		b.Images = append(b.Images, BinaryImage{Architecture: header.cpu.String(), Subtype: fmt.Sprintf("0x%x", header.subtype),
			File: FileRange{Offset: fmt.Sprintf("0x%x", header.offset), Size: header.size}})
		header.index = len(b.Images)
		b.inspectMachO(member.file, header.binaryImageRange, len(usable)-index)
	}
}

func machOFatSlices(data []byte) []machOSlice {
	if len(data) < 8 {
		return nil
	}
	magic := binary.BigEndian.Uint32(data)
	var order binary.ByteOrder = binary.BigEndian
	entrySize := 20
	switch magic {
	case macho.MagicFat:
	case machOFat64:
		entrySize = 32
	case machOFatSwapped:
		order = binary.LittleEndian
	case machOFat64Swap:
		entrySize, order = 32, binary.LittleEndian
	default:
		return nil
	}
	count := order.Uint32(data[4:])
	if count == 0 || count > maxMachOImages || len(data) < 8+int(count)*entrySize {
		return nil
	}
	headerSize := uint64(8 + int(count)*entrySize)
	members := make([]machOSlice, 0, count)
	seen := make(map[machOArchitecture]bool)
	for index := range int(count) {
		entry := data[8+index*entrySize:]
		architecture := machOArchitecture{macho.Cpu(order.Uint32(entry)), order.Uint32(entry[4:])}
		offset, size := uint64(order.Uint32(entry[8:])), uint64(order.Uint32(entry[12:]))
		if entrySize == 32 {
			offset, size = order.Uint64(entry[8:]), order.Uint64(entry[16:])
		}
		if offset < headerSize || offset >= uint64(len(data)) || size == 0 || size > uint64(len(data))-offset || seen[architecture] {
			return nil
		}
		seen[architecture] = true
		members = append(members, machOSlice{architecture, binaryImageRange{offset: offset, size: size}})
	}
	ordered := slices.Clone(members)
	slices.SortFunc(ordered, func(a, b machOSlice) int { return cmp.Compare(a.offset, b.offset) })
	for index := 1; index < len(ordered); index++ {
		if ordered[index].offset < ordered[index-1].offset+ordered[index-1].size {
			return nil
		}
	}
	return members
}
