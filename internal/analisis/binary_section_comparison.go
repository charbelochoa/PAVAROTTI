package analisis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"slices"
	"strconv"
	"strings"

	"pavarotti/internal/caso"
	"pavarotti/internal/triaje"
)

const BinarySectionComparisonSchema = "pavarotti.binary-section-comparison.v1"

var (
	ErrBinarySectionRequest   = errors.New("indica las revisiones base y actual de dos binarios")
	ErrBinarySectionPair      = errors.New("elige binarios del mismo formato y arquitectura, o dos Mach-O universales")
	ErrBinarySectionInventory = errors.New("la comparación requiere inventarios de secciones completos que coincidan con la inspección guardada")
	ErrBinarySectionWork      = errors.New("los intervalos de sección exceden 64 MiB de verificación por archivo")
)

type BinarySectionTarget struct {
	RecordID string `json:"record_id"`
	Revision int    `json:"revision"`
}

type BinarySectionSelection struct {
	Baseline BinarySectionTarget `json:"baseline"`
	Current  BinarySectionTarget `json:"current"`
}

type BinarySectionSource struct {
	BinarySectionTarget
	Name             string `json:"name"`
	SHA256           string `json:"sha256"`
	InspectionSHA256 string `json:"inspection_sha256"`
	Format           string `json:"format"`
	Architecture     string `json:"architecture"`
	Size             int    `json:"size"`
	Sections         int    `json:"sections"`
}

type BinarySectionEntry struct {
	Index    int               `json:"index"`
	Image    int               `json:"image"`
	Address  string            `json:"address"`
	Size     string            `json:"size"`
	File     *triaje.FileRange `json:"file,omitempty"`
	SHA256   string            `json:"sha256,omitempty"`
	Citation *BinaryCitation   `json:"citation,omitempty"`
}

type BinarySectionChange struct {
	Name         string               `json:"name"`
	Architecture string               `json:"architecture"`
	Subtype      string               `json:"subtype,omitempty"`
	State        string               `json:"state"`
	Changes      []string             `json:"changes,omitempty"`
	Baseline     []BinarySectionEntry `json:"baseline"`
	Current      []BinarySectionEntry `json:"current"`
}

type BinarySectionComparison struct {
	Schema   string                `json:"schema"`
	Baseline BinarySectionSource   `json:"baseline"`
	Current  BinarySectionSource   `json:"current"`
	Rows     []BinarySectionChange `json:"rows"`
}

type binarySectionIdentity struct {
	name, architecture, subtype string
}

type BinarySectionInventory struct {
	source BinarySectionSource
	groups map[binarySectionIdentity][]BinarySectionEntry
}

type BinarySectionReader struct {
	original []byte
}

func ReadBinarySections(ctx context.Context, store *caso.Store, target BinarySectionTarget, sample io.Reader) (BinarySectionInventory, error) {
	var reader BinarySectionReader
	return reader.Read(ctx, store, target, sample)
}

func (reader *BinarySectionReader) Read(ctx context.Context, store *caso.Store, target BinarySectionTarget, sample io.Reader) (BinarySectionInventory, error) {
	if target.RecordID == "" || target.Revision < 1 || sample == nil {
		return BinarySectionInventory{}, ErrBinarySectionRequest
	}
	record, saved, err := loadBinaryInspection(ctx, store, target.RecordID, target.Revision)
	if err != nil {
		return BinarySectionInventory{}, err
	}
	data, err := readVerifiedBinaryBuffered(ctx, sample, saved.Size, record.SHA256, reader.original)
	if err != nil {
		return BinarySectionInventory{}, err
	}
	reader.original = data
	layout := triaje.InspectLayout(data)
	if err := ctx.Err(); err != nil {
		return BinarySectionInventory{}, err
	}
	switch layout.Format {
	case "ELF", "PE", "Mach-O", "Mach-O universal":
	default:
		return BinarySectionInventory{}, ErrBinarySectionPair
	}
	if layout.SectionCount != len(layout.Sections) || layout.UnreadableImages != 0 || saved.UnreadableImages != 0 ||
		(saved.SectionCount != 0 && saved.SectionCount != layout.SectionCount) ||
		layout.Format != saved.Format || layout.Architecture != saved.Architecture ||
		!slices.Equal(layout.Images, saved.Images) || !slices.EqualFunc(layout.Sections, saved.Sections, sameBinarySection) {
		return BinarySectionInventory{}, ErrBinarySectionInventory
	}
	name := record.SourceID
	if name == "" {
		name = record.Title
	}
	source := BinarySectionSource{
		BinarySectionTarget: BinarySectionTarget{RecordID: record.ID, Revision: record.Revision},
		Name:                name, SHA256: record.SHA256, InspectionSHA256: caso.Hash([]byte(record.Details)),
		Format: layout.Format, Architecture: layout.Architecture, Size: layout.Size, Sections: layout.SectionCount,
	}
	inventory := BinarySectionInventory{source: source, groups: make(map[binarySectionIdentity][]BinarySectionEntry)}
	digests := make(map[triaje.FileRange]string)
	var bytesHashed uint64
	for index, section := range layout.Sections {
		if err := ctx.Err(); err != nil {
			return BinarySectionInventory{}, err
		}
		identity := binarySectionIdentity{name: section.Name, architecture: layout.Architecture}
		if section.Image > 0 {
			image := layout.Images[section.Image-1]
			identity.architecture, identity.subtype = image.Architecture, image.Subtype
		}
		entry := BinarySectionEntry{Index: index, Image: section.Image, Address: section.Address,
			Size: strconv.FormatUint(section.Size, 10), File: section.File}
		if section.File != nil {
			region := *section.File
			digest, saved := digests[region]
			if !saved {
				offset, valid := triaje.ParseBinaryHex(region.Offset)
				if !valid || offset >= uint64(len(data)) || region.Size == 0 || region.Size > uint64(len(data))-offset {
					return BinarySectionInventory{}, ErrBinarySectionInventory
				}
				bytesHashed += region.Size
				if bytesHashed > 2*triaje.MaxBinaryBytes {
					return BinarySectionInventory{}, ErrBinarySectionWork
				}
				digest, err = hashBinarySection(ctx, data[offset:offset+region.Size])
				if err != nil {
					return BinarySectionInventory{}, err
				}
				digests[region] = digest
			}
			entry.SHA256 = digest
			citation := binaryCitation(record, source.InspectionSHA256, "seccion", index, region.Offset)
			entry.Citation = &citation
		}
		inventory.groups[identity] = append(inventory.groups[identity], entry)
	}
	return inventory, nil
}

func hashBinarySection(ctx context.Context, data []byte) (string, error) {
	hash := sha256.New()
	for block := range slices.Chunk(data, binaryVerificationBlockSize) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		_, _ = hash.Write(block)
	}
	return hex.EncodeToString(hash.Sum(nil)), ctx.Err()
}

func sameBinarySection(a, b triaje.Section) bool {
	if a.Name != b.Name || a.Image != b.Image || a.Address != b.Address || a.Size != b.Size {
		return false
	}
	return a.File == b.File || (a.File != nil && b.File != nil && *a.File == *b.File)
}

func CompareBinarySections(base, current BinarySectionInventory) (BinarySectionComparison, error) {
	if base.source.Format == "" || base.source.Format != current.source.Format ||
		(base.source.Format != "Mach-O universal" &&
			(base.source.Architecture == "" || base.source.Architecture != current.source.Architecture)) {
		return BinarySectionComparison{}, ErrBinarySectionPair
	}
	comparison := BinarySectionComparison{Schema: BinarySectionComparisonSchema, Baseline: base.source, Current: current.source,
		Rows: make([]BinarySectionChange, 0, len(base.groups)+len(current.groups))}
	for key, entries := range base.groups {
		comparison.Rows = append(comparison.Rows, compareSectionGroup(key, entries, current.groups[key]))
	}
	for key, entries := range current.groups {
		if len(base.groups[key]) == 0 {
			comparison.Rows = append(comparison.Rows, compareSectionGroup(key, nil, entries))
		}
	}
	slices.SortFunc(comparison.Rows, func(a, b BinarySectionChange) int {
		if order := strings.Compare(a.Architecture, b.Architecture); order != 0 {
			return order
		}
		if order := strings.Compare(a.Subtype, b.Subtype); order != 0 {
			return order
		}
		return strings.Compare(a.Name, b.Name)
	})
	return comparison, nil
}

func compareSectionGroup(key binarySectionIdentity, base, current []BinarySectionEntry) BinarySectionChange {
	row := BinarySectionChange{Name: key.name, Architecture: key.architecture, Subtype: key.subtype, Baseline: base, Current: current}
	switch {
	case len(base) == 0:
		row.State, row.Baseline = "agregada", []BinarySectionEntry{}
	case len(current) == 0:
		row.State, row.Current = "ausente", []BinarySectionEntry{}
	case len(base) != 1 || len(current) != 1:
		row.State = "ambigua"
	default:
		row.State, row.Changes = compareSectionEntries(base[0], current[0])
	}
	return row
}

func compareSectionEntries(base, current BinarySectionEntry) (string, []string) {
	var changes []string
	state := "igual"
	if base.Address != current.Address {
		changes = append(changes, "direccion")
		state = "movida"
	}
	if base.File != nil && current.File != nil && base.File.Offset != current.File.Offset {
		changes = append(changes, "desplazamiento")
		state = "movida"
	}
	if base.Size != current.Size {
		changes = append(changes, "tamano_declarado")
		state = "modificada"
	}
	if (base.File == nil) != (current.File == nil) {
		changes = append(changes, "respaldo_fisico")
		state = "modificada"
	}
	if base.File != nil && current.File != nil && base.File.Size != current.File.Size {
		changes = append(changes, "tamano_fisico")
		state = "modificada"
	}
	if base.File != nil && current.File != nil && base.SHA256 != current.SHA256 {
		changes = append(changes, "contenido")
		state = "modificada"
	}
	return state, changes
}
