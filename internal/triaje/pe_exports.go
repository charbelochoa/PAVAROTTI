package triaje

import (
	"cmp"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"math"
	"slices"
	"sort"
)

const maxPEExportsScanned = 65536

type peExportRegion struct {
	start, end uint64
	offset     uint64
	backing    uint64
	name       string
}

type peExportImage struct {
	data    []byte
	regions []peExportRegion
}

func (b *Binary) peExports(file *pe.File, data []byte) {
	const directorySize = 40
	directory, headers := peExportDirectory(file)
	start, size := uint64(directory.VirtualAddress), uint64(directory.Size)
	if start == 0 || size < directorySize || start+size > math.MaxUint32+1 {
		return
	}
	image := peExportImage{data: data, regions: peExportRegions(file.Sections, headers, uint64(len(data)))}
	header := image.bytes(start, directorySize)
	if header == nil {
		return
	}
	order := binary.LittleEndian
	base, functionCount, nameCount := order.Uint32(header[16:]), order.Uint32(header[20:]), order.Uint32(header[24:])
	if functionCount == 0 || uint64(base)+uint64(functionCount)-1 > math.MaxUint32 {
		return
	}
	functions := image.bytes(uint64(order.Uint32(header[28:])), uint64(min(functionCount, maxPEExportsScanned))*4)
	if len(functions) == 0 {
		return
	}
	b.SymbolsLimited = b.SymbolsLimited || functionCount > maxPEExportsScanned || nameCount > maxPEExportsScanned
	keep := func(index uint32, name string) bool {
		rva := uint64(order.Uint32(functions[index*4:]))
		if rva == 0 {
			return true
		}
		ordinal := base + index
		symbol := Symbol{Name: name, Kind: "Exportación PE", Ordinal: &ordinal}
		if rva >= start && rva < start+size {
			symbol.Forwarder = image.text(rva, start+size-rva)
			if symbol.Forwarder == "" {
				return true
			}
		} else {
			region := image.region(rva)
			if region == nil {
				return true
			}
			symbol.Section = region.name
			if delta := rva - region.start; delta < region.backing {
				symbol.Offset = fmt.Sprintf("0x%x", region.offset+delta)
			}
		}
		return b.addSymbol(symbol, rva)
	}
	names := make(map[uint32]bool)
	scanNames := uint64(min(nameCount, maxPEExportsScanned))
	if scanNames > 0 {
		nameRVA := image.bytes(uint64(order.Uint32(header[32:])), scanNames*4)
		ordinals := image.bytes(uint64(order.Uint32(header[36:])), scanNames*2)
		if nameRVA == nil || ordinals == nil {
			return
		}
		for n := range scanNames {
			index := uint32(order.Uint16(ordinals[n*2:]))
			if uint64(index) >= uint64(len(functions))/4 {
				continue
			}
			names[index] = true
			name := image.text(uint64(order.Uint32(nameRVA[n*4:])), maxSymbolName+1)
			if name != "" && !keep(index, name) {
				return
			}
		}
	}
	if nameCount > maxPEExportsScanned {
		return
	}
	for index := range min(functionCount, maxPEExportsScanned) {
		if !names[index] && !keep(index, fmt.Sprintf("Ordinal %d", base+index)) {
			return
		}
	}
}

func peExportDirectory(file *pe.File) (pe.DataDirectory, uint32) {
	switch header := file.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if header.NumberOfRvaAndSizes > pe.IMAGE_DIRECTORY_ENTRY_EXPORT {
			return header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT], header.SizeOfHeaders
		}
	case *pe.OptionalHeader64:
		if header.NumberOfRvaAndSizes > pe.IMAGE_DIRECTORY_ENTRY_EXPORT {
			return header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT], header.SizeOfHeaders
		}
	}
	return pe.DataDirectory{}, 0
}

func peExportRegions(sections []*pe.Section, headers uint32, size uint64) []peExportRegion {
	regions := make([]peExportRegion, 0, len(sections)+1)
	if headers != 0 {
		regions = append(regions, peExportRegion{end: uint64(headers), backing: min(size, uint64(headers)), name: "Cabeceras PE"})
	}
	for _, section := range sections {
		start, virtual, raw := uint64(section.VirtualAddress), uint64(section.VirtualSize), uint64(section.Size)
		extent := max(virtual, raw)
		if extent == 0 {
			continue
		}
		if start+extent > math.MaxUint32+1 {
			return nil
		}
		region := peExportRegion{start: start, end: start + extent, offset: uint64(section.Offset), name: section.Name}
		if region.offset > 0 && region.offset <= size && raw <= size-region.offset {
			region.backing = raw
			if virtual > 0 {
				region.backing = min(raw, virtual)
			}
		}
		regions = append(regions, region)
	}
	slices.SortFunc(regions, func(a, b peExportRegion) int { return cmp.Compare(a.start, b.start) })
	for index := 1; index < len(regions); index++ {
		if regions[index].start < regions[index-1].end {
			return nil
		}
	}
	return regions
}

func (p peExportImage) region(rva uint64) *peExportRegion {
	index := sort.Search(len(p.regions), func(index int) bool { return p.regions[index].end > rva })
	if index < len(p.regions) && p.regions[index].start <= rva {
		return &p.regions[index]
	}
	return nil
}

func (p peExportImage) bytes(rva, size uint64) []byte {
	region := p.region(rva)
	if rva == 0 || region == nil {
		return nil
	}
	delta := rva - region.start
	if delta >= region.backing || size > region.backing-delta {
		return nil
	}
	return p.data[region.offset+delta : region.offset+delta+size]
}

func (p peExportImage) text(rva, limit uint64) string {
	region := p.region(rva)
	if rva == 0 || region == nil {
		return ""
	}
	delta := rva - region.start
	if delta >= region.backing {
		return ""
	}
	start := region.offset + delta
	text := p.data[start : start+min(region.backing-delta, limit, maxSymbolName+1)]
	end := slices.Index(text, byte(0))
	if end <= 0 || !symbolLabel(string(text[:end])) {
		return ""
	}
	return string(text[:end])
}
