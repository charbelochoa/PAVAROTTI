package mesa

import (
	"bytes"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"pavarotti/internal/analisis"
	"pavarotti/internal/caso"
	"pavarotti/internal/ingesta"
	"pavarotti/internal/triaje"
)

type sectionPEFixture struct {
	name                  string
	address, offset, size uint32
	data                  string
}

func sectionComparisonPE(t *testing.T, fixtures []sectionPEFixture) []byte {
	t.Helper()
	const header = 0x188
	out := make([]byte, max(0x1000, header+40*len(fixtures)))
	copy(out, windowFixturePE(t)[:header])
	binary.LittleEndian.PutUint16(out[0x86:], uint16(len(fixtures)))
	clear(out[0x8c:0x94])
	for index, fixture := range fixtures {
		table := out[header+40*index:]
		copy(table[:8], fixture.name)
		binary.LittleEndian.PutUint32(table[8:], fixture.size)
		binary.LittleEndian.PutUint32(table[12:], fixture.address)
		binary.LittleEndian.PutUint32(table[16:], uint32(len(fixture.data)))
		binary.LittleEndian.PutUint32(table[20:], fixture.offset)
		copy(out[fixture.offset:], fixture.data)
	}
	return out
}

func sectionComparisonFixtures(t *testing.T) ([]byte, []byte) {
	t.Helper()
	base := sectionComparisonPE(t, []sectionPEFixture{
		{".text", 0x1000, 0x600, 4, "BASE"}, {".data", 0x2000, 0x680, 4, "MOVE"},
		{".stable", 0x3000, 0x700, 4, "SAME"}, {".bss", 0x4000, 0, 32, ""},
		{".old", 0x5000, 0x780, 3, "OLD"}, {".dupe", 0x6000, 0x800, 3, "ONE"},
		{".dupe", 0x6100, 0x880, 3, "TWO"},
	})
	current := sectionComparisonPE(t, []sectionPEFixture{
		{".text", 0x1000, 0x600, 4, "EDIT"}, {".data", 0x2100, 0x6a0, 4, "MOVE"},
		{".stable", 0x3000, 0x700, 4, "SAME"}, {".bss", 0x4000, 0, 64, ""},
		{".new", 0x5000, 0x780, 3, "NEW"}, {".dupe", 0x6000, 0x800, 3, "ONE"},
	})
	return base, current
}

func saveSectionComparisonBinary(t *testing.T, store *caso.Store, name string, data []byte, adjust func(*triaje.Binary)) analisis.BinarySectionTarget {
	t.Helper()
	records, err := ingesta.ParseNamed("binario", bytes.NewReader(data), name)
	if err != nil {
		t.Fatal(err)
	}
	if adjust != nil {
		var report triaje.Binary
		if err := json.Unmarshal([]byte(records[0].Details), &report); err != nil {
			t.Fatal(err)
		}
		adjust(&report)
		body, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		records[0].Details = string(body)
	}
	if err := store.Save(records); err != nil {
		t.Fatal(err)
	}
	page, err := store.Page(t.Context(), caso.PageRequest{Kind: "binario"})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range page.Rows {
		if row.SourceID == name {
			return analisis.BinarySectionTarget{RecordID: row.ID, Revision: 1}
		}
	}
	t.Fatalf("registro del archivo %s no encontrado", name)
	return analisis.BinarySectionTarget{}
}

func readSectionComparison(t *testing.T, store *caso.Store, target analisis.BinarySectionTarget, data []byte) analisis.BinarySectionInventory {
	t.Helper()
	inventory, err := analisis.ReadBinarySections(t.Context(), store, target, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	return inventory
}

func TestBinarySectionComparisonDistinguishesContentAndLayout(t *testing.T) {
	store, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	base, current := sectionComparisonFixtures(t)
	prior := saveSectionComparisonBinary(t, store, "base.exe", base, func(report *triaje.Binary) { report.SectionCount = 0 })
	later := saveSectionComparisonBinary(t, store, "actual.exe", current, nil)
	before := readSectionComparison(t, store, prior, base)
	after := readSectionComparison(t, store, later, current)
	comparison, err := analisis.CompareBinarySections(before, after)
	if err != nil || comparison.Schema != analisis.BinarySectionComparisonSchema || len(comparison.Rows) != 7 ||
		comparison.Baseline.Sections != 7 || comparison.Current.Sections != 6 ||
		comparison.Baseline.SHA256 == comparison.Current.SHA256 {
		t.Fatalf("comparación: %+v, %v", comparison, err)
	}
	expected := map[string]string{".text": "modificada", ".data": "movida", ".stable": "igual", ".bss": "modificada",
		".old": "ausente", ".new": "agregada", ".dupe": "ambigua"}
	byName := make(map[string]analisis.BinarySectionChange)
	for _, row := range comparison.Rows {
		if row.State != expected[row.Name] {
			t.Fatalf("estado de %s: %s", row.Name, row.State)
		}
		byName[row.Name] = row
	}
	code := byName[".text"]
	if !reflect.DeepEqual(code.Changes, []string{"contenido"}) || code.Baseline[0].SHA256 != caso.Hash([]byte("BASE")) ||
		code.Current[0].SHA256 != caso.Hash([]byte("EDIT")) {
		t.Fatalf("huella física: %+v", code)
	}
	moved := byName[".data"]
	if !reflect.DeepEqual(moved.Changes, []string{"direccion", "desplazamiento"}) ||
		moved.Baseline[0].SHA256 != moved.Current[0].SHA256 ||
		moved.Baseline[0].File.Offset != "0x680" || moved.Current[0].File.Offset != "0x6a0" {
		t.Fatalf("desplazamientos: %+v", moved)
	}
	citation := moved.Current[0].Citation
	verified, err := analisis.CiteBinary(t.Context(), store, later.RecordID, later.Revision, "seccion", moved.Current[0].Index)
	if err != nil || citation == nil || *citation != verified {
		t.Fatalf("cita de sección: %+v, %v", citation, err)
	}
	memory := byName[".bss"]
	if !reflect.DeepEqual(memory.Changes, []string{"tamano_declarado"}) ||
		memory.Baseline[0].SHA256 != "" || memory.Current[0].Citation != nil {
		t.Fatalf("sección sin bytes: %+v", memory)
	}
	if duplicate := byName[".dupe"]; len(duplicate.Baseline) != 2 || len(duplicate.Current) != 1 || len(duplicate.Changes) != 0 {
		t.Fatalf("secciones ambiguas: %+v", duplicate)
	}
	if _, err := analisis.ReadBinarySections(t.Context(), store, later, bytes.NewReader(base)); !errors.Is(err, analisis.ErrBinaryWindowSample) {
		t.Fatalf("archivo de otra revisión: %v", err)
	}
}

func TestBinarySectionComparisonRejectsIncompleteOrForgedLayouts(t *testing.T) {
	store, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	base, _ := sectionComparisonFixtures(t)
	broken := saveSectionComparisonBinary(t, store, "alterado.exe", base, func(report *triaje.Binary) {
		report.Sections[0].File.Offset = "0x601"
	})
	if _, err := analisis.ReadBinarySections(t.Context(), store, broken, bytes.NewReader(base)); !errors.Is(err, analisis.ErrBinarySectionInventory) {
		t.Fatalf("inspección alterada: %v", err)
	}
	truncated := sectionComparisonPE(t, make([]sectionPEFixture, 257))
	large := saveSectionComparisonBinary(t, store, "truncado.exe", truncated, nil)
	if _, err := analisis.ReadBinarySections(t.Context(), store, large, bytes.NewReader(truncated)); !errors.Is(err, analisis.ErrBinarySectionInventory) {
		t.Fatalf("secciones truncadas: %v", err)
	}
	base = append(base, 0x01)
	other := bytes.Clone(base)
	binary.LittleEndian.PutUint16(other[0x84:], pe.IMAGE_FILE_MACHINE_ARM64)
	left := readSectionComparison(t, store, saveSectionComparisonBinary(t, store, "x86.exe", base, nil), base)
	right := readSectionComparison(t, store, saveSectionComparisonBinary(t, store, "arm.exe", other, nil), other)
	if _, err := analisis.CompareBinarySections(left, right); !errors.Is(err, analisis.ErrBinarySectionPair) {
		t.Fatalf("arquitecturas distintas: %v", err)
	}
}

func sectionComparisonUniversal(t *testing.T, cpus []macho.Cpu) []byte {
	t.Helper()
	data := make([]byte, 0x3000)
	binary.BigEndian.PutUint32(data, macho.MagicFat)
	binary.BigEndian.PutUint32(data[4:], uint32(len(cpus)))
	for index, cpu := range cpus {
		offset := uint32(0x1000 * (index + 1))
		region := data[offset : offset+0x300]
		fat := data[8+20*index:]
		binary.BigEndian.PutUint32(fat, uint32(cpu))
		binary.BigEndian.PutUint32(fat[4:], uint32(cpu)%8)
		binary.BigEndian.PutUint32(fat[8:], offset)
		binary.BigEndian.PutUint32(fat[12:], uint32(len(region)))
		binary.BigEndian.PutUint32(fat[16:], 12)
		section := macho.Section64{Addr: 0x1000, Size: 16, Offset: 0x180}
		copy(section.Name[:], "__text")
		copy(section.Seg[:], "__TEXT")
		segment := macho.Segment64{Cmd: macho.LoadCmdSegment64, Memsz: 0x300, Filesz: 0x300, Nsect: 1}
		segment.Len = uint32(binary.Size(segment) + binary.Size(section))
		copy(segment.Name[:], "__TEXT")
		header := macho.FileHeader{Magic: macho.Magic64, Cpu: cpu, SubCpu: uint32(cpu) % 8, Type: macho.TypeExec, Ncmd: 1, Cmdsz: segment.Len}
		buffer := bytes.NewBuffer(region[:0])
		for _, item := range []any{header, uint32(0), segment, section} {
			if err := binary.Write(buffer, binary.LittleEndian, item); err != nil {
				t.Fatal(err)
			}
		}
		binary.LittleEndian.PutUint32(region[0x180:], uint32(cpu))
	}
	return data
}

func TestBinarySectionComparisonMatchesReorderedUniversalImages(t *testing.T) {
	store, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	base := sectionComparisonUniversal(t, []macho.Cpu{macho.CpuAmd64, macho.CpuArm64})
	current := sectionComparisonUniversal(t, []macho.Cpu{macho.CpuArm64, macho.CpuAmd64})
	before := readSectionComparison(t, store, saveSectionComparisonBinary(t, store, "primero", base, nil), base)
	after := readSectionComparison(t, store, saveSectionComparisonBinary(t, store, "segundo", current, nil), current)
	comparison, err := analisis.CompareBinarySections(before, after)
	if err != nil || len(comparison.Rows) != 2 || comparison.Baseline.Format != "Mach-O universal" {
		t.Fatalf("imagen universal: %+v, %v", comparison, err)
	}
	for _, row := range comparison.Rows {
		if row.State != "movida" || len(row.Baseline) != 1 || len(row.Current) != 1 ||
			row.Baseline[0].Image == row.Current[0].Image || row.Baseline[0].SHA256 != row.Current[0].SHA256 || row.Subtype == "" {
			t.Fatalf("emparejamiento por arquitectura: %+v", row)
		}
	}
}
