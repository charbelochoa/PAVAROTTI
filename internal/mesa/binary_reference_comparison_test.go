package mesa

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"pavarotti/internal/analisis"
	"pavarotti/internal/caso"
	"pavarotti/internal/ingesta"
	"pavarotti/internal/terminal"
	"pavarotti/internal/triaje"
)

func comparisonFixture(t *testing.T) (*caso.Store, []byte, analisis.BinaryReferenceReport, analisis.BinaryReferenceReport) {
	t.Helper()
	store, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	sample := windowFixturePE(t)
	order := binary.LittleEndian
	order.PutUint32(sample[0x98+16:], 0x1000)
	for _, jump := range []struct{ from, to int }{{0, 128}, {48, 300}, {64, 300}, {128, 300}} {
		sample[0x200+jump.from] = 0xe9
		order.PutUint32(sample[0x201+jump.from:], uint32(jump.to-jump.from-5))
	}
	id := saveWindowSample(t, store, sample)
	inspection := triaje.Inspect(sample)
	index := slices.IndexFunc(inspection.Instructions, func(row triaje.Instruction) bool { return row.Offset == "0x230" })
	if index < 0 {
		t.Fatal("falta el origen archivado")
	}
	draft := analisis.BinaryReferenceReport{Schema: analisis.BinaryReferenceSchema, RecordID: id, Revision: 1, SHA256: inspection.SHA256,
		Destination: analisis.BinaryReferenceLocation{Kind: "entrada", Path: "0.0", Address: "0x112c", Offset: "0x32c"},
		Origins: []analisis.BinaryReferenceLocation{
			{Kind: "instruccion", Index: index, Address: "0x1030", Offset: "0x230"},
			{Kind: "entrada", Row: 56, Address: "0x1040", Offset: "0x240"},
		}}
	seal := func(report analisis.BinaryReferenceReport) analisis.BinaryReferenceReport {
		t.Helper()
		review, err := analisis.ReviewBinaryReferences(t.Context(), store, report, bytes.NewReader(sample), false)
		if err != nil {
			t.Fatal(err)
		}
		return review.Report
	}
	baseline := seal(draft)
	copyRecords, err := ingesta.ParseNamed("binario", bytes.NewReader(sample), "segunda-muestra.exe")
	if err != nil || len(copyRecords) != 1 {
		t.Fatalf("copia de la evidencia: %v", err)
	}
	compact, err := json.Marshal(inspection)
	if err != nil {
		t.Fatal(err)
	}
	copyRecords[0].Details = string(compact)
	copyRecords[0].BinaryListing = 0
	if err := store.Save(copyRecords); err != nil {
		t.Fatal(err)
	}
	page, err := store.Page(t.Context(), caso.PageRequest{Kind: "binario"})
	if err != nil || len(page.Rows) != 2 {
		t.Fatalf("muestras: %+v, %v", page, err)
	}
	draft.RecordID = page.Rows[0].ID
	if draft.RecordID == id {
		draft.RecordID = page.Rows[1].ID
	}
	draft.Destination = analisis.BinaryReferenceLocation{Kind: "simbolo", Address: "0x112c", Offset: "0x32c"}
	draft.Origins = []analisis.BinaryReferenceLocation{
		{Kind: "entrada", Path: "0", Address: "0x1080", Offset: "0x280"},
		{Kind: "entrada", Row: 44, Address: "0x1030", Offset: "0x230"},
	}
	return store, sample, baseline, seal(draft)
}

func TestCompareBinaryReferencesKeepsBothWindowCitations(t *testing.T) {
	store, sample, baseline, current := comparisonFixture(t)
	compare := func(a, b analisis.BinaryReferenceReport, original []byte) (analisis.BinaryReferenceComparison, error) {
		return analisis.CompareBinaryReferences(t.Context(), store, a, b, bytes.NewReader(original))
	}
	diff, err := compare(baseline, current, sample)
	if err != nil || diff.Schema != analisis.BinaryReferenceComparisonSchema || diff.DestinationOffset != "0x32c" ||
		diff.Shared != 1 || diff.Added != 1 || diff.Absent != 1 || len(diff.Rows) != 3 ||
		diff.Baseline.RecordID == diff.Current.RecordID || diff.Baseline.InspectionSHA256 == diff.Current.InspectionSHA256 ||
		diff.Baseline.ReportSHA256 != baseline.ReportSHA256 ||
		diff.Current.ReportSHA256 != current.ReportSHA256 {
		t.Fatalf("comparación: %+v, %v", diff, err)
	}
	common, absent, added := diff.Rows[0], diff.Rows[1], diff.Rows[2]
	if common.State != "comun" || common.Baseline == nil || common.Current == nil ||
		*common.Baseline != baseline.Origins[0] || *common.Current != current.Origins[1] ||
		common.Baseline.WindowSHA256 == common.Current.WindowSHA256 || common.Instruction.Target != "0x112c" ||
		absent.State != "ausente" || absent.Current != nil || absent.Baseline == nil || absent.Instruction.Offset != "0x240" ||
		added.State != "agregado" || added.Baseline != nil || added.Current == nil || added.Instruction.Offset != "0x280" {
		t.Fatalf("orígenes: %+v", diff.Rows)
	}
	same, err := compare(baseline, baseline, sample)
	if err != nil || same.Shared != 2 || same.Added != 0 || same.Absent != 0 {
		t.Fatalf("mismo informe: %+v, %v", same, err)
	}
	changed := bytes.Clone(sample)
	changed[0x230] ^= 1
	if _, err := compare(baseline, current, changed); !errors.Is(err, analisis.ErrBinaryWindowSample) {
		t.Fatalf("muestra alterada: %v", err)
	}
	tampered := current
	tampered.Destination.Offset = "0x32d"
	if _, err := compare(baseline, tampered, sample); !errors.Is(err, analisis.ErrBinaryReferenceReport) {
		t.Fatalf("informe alterado: %v", err)
	}
	incompatible := current
	incompatible.Destination = analisis.BinaryReferenceLocation{Kind: "entrada", Path: "0", Address: "0x1080", Offset: "0x280"}
	incompatible.Origins = []analisis.BinaryReferenceLocation{{Kind: "entrada", Address: "0x1000", Offset: "0x200"}}
	review, err := analisis.ReviewBinaryReferences(t.Context(), store, incompatible, bytes.NewReader(sample), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := compare(baseline, review.Report, sample); !errors.Is(err, analisis.ErrBinaryReferenceComparison) {
		t.Fatalf("destinos distintos: %v", err)
	}
}

func TestCompareBinaryReferencesAcrossInterfaces(t *testing.T) {
	store, sample, baseline, current := comparisonFixture(t)
	const host = "127.0.0.1:8443"
	handler := Handler(host, Settings{}, store, testResources)
	post := func(later analisis.BinaryReferenceReport) *httptest.ResponseRecorder {
		t.Helper()
		var body bytes.Buffer
		form := multipart.NewWriter(&body)
		for _, field := range []struct {
			name   string
			report analisis.BinaryReferenceReport
		}{{"base", baseline}, {"actual", later}} {
			manifest, err := form.CreateFormField(field.name)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.NewEncoder(manifest).Encode(field.report); err != nil {
				t.Fatal(err)
			}
		}
		original, err := form.CreateFormFile("archivo", "muestra.exe")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := original.Write(sample); err != nil {
			t.Fatal(err)
		}
		if err := form.Close(); err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "http://"+host+"/api/referencias-binarias/comparar", &body)
		request.Header.Set("Origin", "http://"+host)
		request.Header.Set("Content-Type", form.FormDataContentType())
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	response := post(current)
	var web analisis.BinaryReferenceComparison
	if err := json.Unmarshal(response.Body.Bytes(), &web); response.Code != http.StatusOK || err != nil || web.Shared != 1 {
		t.Fatalf("web: %d %s: %v", response.Code, response.Body, err)
	}
	tampered := current
	tampered.ReportSHA256 = ""
	if response := post(tampered); response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("informe sin sello: %d %s", response.Code, response.Body)
	}
	folder := t.TempDir()
	basePath, currentPath, samplePath := filepath.Join(folder, "base.json"), filepath.Join(folder, "actual.json"), filepath.Join(folder, "muestra.exe")
	for path, report := range map[string]analisis.BinaryReferenceReport{basePath: baseline, currentPath: current} {
		encoded, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(samplePath, sample, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	_, err := terminal.Run([]string{"comparar-referencias", "--base", basePath, "--actual", currentPath, "--archivo", samplePath},
		&stdout, &stderr, func() (*caso.Store, error) { return store, nil })
	if err != nil {
		t.Fatalf("CLI: %v, %s", err, &stderr)
	}
	var cli analisis.BinaryReferenceComparison
	if err := json.Unmarshal(stdout.Bytes(), &cli); err != nil || !reflect.DeepEqual(cli, web) {
		t.Fatalf("comparación CLI: %+v, %v", cli, err)
	}
}
