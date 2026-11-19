package triaje

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxBinarySymbols = 2048
	maxSymbolName    = 256
)

type Symbol struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Address string `json:"address"`
	Section string `json:"section,omitempty"`
	Offset  string `json:"offset,omitempty"`
}

func (b *Binary) addSymbol(name, kind string, address uint64, section, offset string) bool {
	if name == "" || !symbolLabel(name) {
		return true
	}
	if len(b.Symbols) == maxBinarySymbols {
		b.SymbolsLimited = true
		return false
	}
	if !symbolLabel(section) {
		section = ""
	}
	b.Symbols = append(b.Symbols, Symbol{Name: name, Kind: kind, Address: fmt.Sprintf("0x%x", address), Section: section, Offset: offset})
	return true
}

func symbolLabel(value string) bool {
	return len(value) <= maxSymbolName && utf8.ValidString(value) && !strings.ContainsFunc(value, func(r rune) bool {
		return unicode.IsControl(r) || unicode.In(r, unicode.Cf)
	})
}

func (b *Binary) elfSymbols(file *elf.File, data []byte) {
	entrySize := elf.Sym64Size
	if file.Class == elf.ELFCLASS32 {
		entrySize = elf.Sym32Size
	}
	for _, tableType := range []elf.SectionType{elf.SHT_SYMTAB, elf.SHT_DYNSYM} {
		table := file.SectionByType(tableType)
		if table == nil || table.Link == 0 || int64(table.Link) >= int64(len(file.Sections)) {
			continue
		}
		names := file.Sections[table.Link]
		if names.Type != elf.SHT_STRTAB {
			continue
		}
		entries, namesData := elfFileBytes(table, data), elfFileBytes(names, data)
		if len(entries) < entrySize || len(entries)%entrySize != 0 || len(namesData) == 0 {
			continue
		}
		const maxScanned = 65536
		scanEnd := min(len(entries), entrySize*(maxScanned+1))
		b.SymbolsLimited = b.SymbolsLimited || scanEnd < len(entries)
		for index := entrySize; index < scanEnd; index += entrySize {
			if !b.elfSymbol(file, entries[index:index+entrySize], namesData) {
				return
			}
		}
		if len(b.Symbols) != 0 {
			return
		}
	}
}

func (b *Binary) elfSymbol(file *elf.File, entry, names []byte) bool {
	order := file.ByteOrder
	var info byte
	var sectionIndex uint16
	var address uint64
	if len(entry) == elf.Sym32Size {
		info, sectionIndex, address = entry[12], order.Uint16(entry[14:]), uint64(order.Uint32(entry[4:]))
	} else {
		info, sectionIndex, address = entry[4], order.Uint16(entry[6:]), order.Uint64(entry[8:])
	}
	kind := elf.ST_TYPE(info)
	if sectionIndex == 0 || sectionIndex >= uint16(elf.SHN_LORESERVE) || int(sectionIndex) >= len(file.Sections) ||
		kind == elf.STT_FILE || kind == elf.STT_SECTION {
		return true
	}
	nameAt := uint64(order.Uint32(entry))
	if nameAt >= uint64(len(names)) {
		return true
	}
	text := names[nameAt:min(nameAt+maxSymbolName+1, uint64(len(names)))]
	end := bytes.IndexByte(text, 0)
	if end <= 0 {
		return true
	}
	section := file.Sections[sectionIndex]
	base := section.Addr
	if file.Type == elf.ET_REL {
		base = 0
	}
	position := address
	if file.Machine == elf.EM_ARM && kind == elf.STT_FUNC {
		position &^= 1
	}
	offset := ""
	if position >= base && section.Type != elf.SHT_NOBITS && section.Type != elf.SHT_NULL &&
		section.Flags&elf.SHF_COMPRESSED == 0 && kind != elf.STT_TLS {
		offset = b.fileOffset(section.Offset, section.FileSize, position-base)
	}
	return b.addSymbol(string(text[:end]), kind.String(), address, section.Name, offset)
}

func elfFileBytes(section *elf.Section, data []byte) []byte {
	if section.Flags&elf.SHF_COMPRESSED != 0 || section.Offset >= uint64(len(data)) || section.FileSize > uint64(len(data))-section.Offset {
		return nil
	}
	return data[section.Offset : section.Offset+section.FileSize]
}

func (b *Binary) peSymbols(file *pe.File) {
	for _, symbol := range file.Symbols {
		if symbol.SectionNumber < 1 || int(symbol.SectionNumber) > len(file.Sections) {
			continue
		}
		section := file.Sections[symbol.SectionNumber-1]
		delta := uint64(symbol.Value)
		offset := ""
		if section.Offset != 0 {
			offset = b.fileOffset(uint64(section.Offset), uint64(section.Size), delta)
		}
		kind := "COFF"
		if symbol.Type&0x30 == 0x20 {
			kind = "Función COFF"
		}
		if !b.addSymbol(symbol.Name, kind, uint64(section.VirtualAddress)+delta, section.Name, offset) {
			return
		}
	}
}

func (b *Binary) machOSymbols(file *macho.File) {
	if file.Symtab == nil {
		return
	}
	const (
		debugSymbol = 0xe0
		symbolType  = 0x0e
		defined     = 0x0e
		external    = 0x01
	)
	for _, symbol := range file.Symtab.Syms {
		if symbol.Type&debugSymbol != 0 || symbol.Type&symbolType != defined || symbol.Sect == 0 || int(symbol.Sect) > len(file.Sections) {
			continue
		}
		section := file.Sections[symbol.Sect-1]
		offset := ""
		if symbol.Value >= section.Addr {
			offset = b.fileOffset(uint64(section.Offset), machOFileSize(section), symbol.Value-section.Addr)
		}
		kind := "Local"
		if symbol.Type&external != 0 {
			kind = "Externo"
		}
		if !b.addSymbol(symbol.Name, kind, symbol.Value, section.Seg+"/"+section.Name, offset) {
			return
		}
	}
}

func machOFileSize(section *macho.Section) uint64 {
	const (
		sectionTypeMask     = 0xff
		zeroFill            = 0x1
		gbZeroFill          = 0xc
		threadLocalZeroFill = 0x12
	)
	switch section.Flags & sectionTypeMask {
	case zeroFill, gbZeroFill, threadLocalZeroFill:
		return 0
	}
	return section.Size
}
