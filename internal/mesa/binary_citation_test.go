package mesa

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"pavarotti/internal/analisis"
	"pavarotti/internal/caso"
	"pavarotti/internal/ingesta"
	"pavarotti/internal/terminal"
	"pavarotti/internal/triaje"
)

func TestBinaryCitationUsesStoredRevision(t *testing.T) {
	store, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	records, err := ingesta.ParseNamed("binario", strings.NewReader("\x00Observed evidence string\x00"), "muestra.dat")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(records); err != nil {
		t.Fatal(err)
	}
	page, err := store.Page(t.Context(), caso.PageRequest{Kind: "binario"})
	if err != nil || len(page.Rows) != 1 {
		t.Fatalf("registros: %+v, %v", page, err)
	}
	id := page.Rows[0].ID
	const host = "127.0.0.1:8443"
	handler := Handler(host, Settings{}, store, testResources)
	get := func(query string, status int) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest("GET", "http://"+host+"/api/registro/"+id+"/cita-binaria?"+query, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != status {
			t.Fatalf("%s: %d, esperado %d, respuesta %s", query, response.Code, status, response.Body)
		}
		return response
	}
	result := get("revision=1&tipo=cadena&indice=0", 200)
	expected := analisis.BinaryCitation{Schema: analisis.BinaryCitationSchema, RecordID: id, Revision: 1, SHA256: records[0].SHA256,
		InspectionSHA256: caso.Hash([]byte(records[0].Details)), Kind: "cadena", Index: 0, Offset: "0x1"}
	var web analisis.BinaryCitation
	if err := json.Unmarshal(result.Body.Bytes(), &web); err != nil || web != expected {
		t.Fatalf("cita web: %+v, %v", web, err)
	}
	get("revision=2&tipo=cadena&indice=0", 404)
	get("revision=1&tipo=simbolo&indice=0", 404)
	get("revision=1&tipo=cadena&indice=2", 404)
	get("revision=1&tipo=cadena&indice=-1", 400)
	get("revision=1&tipo=invalido&indice=0", 400)
	var stdout, stderr bytes.Buffer
	handled, err := terminal.Run([]string{"citar-binario", "--id", id, "--revision", "1", "--tipo", "cadena", "--indice", "0"},
		&stdout, &stderr, func() (*caso.Store, error) { return store, nil })
	if !handled || err != nil {
		t.Fatalf("CLI: %v, %s", err, &stderr)
	}
	var cli analisis.BinaryCitation
	if err := json.Unmarshal(stdout.Bytes(), &cli); err != nil || cli != web {
		t.Fatalf("cita CLI: %+v, %v", cli, err)
	}
	if bytes.Contains(stdout.Bytes(), []byte("Observed evidence string")) {
		t.Fatal("la cita incluye el contenido de la evidencia")
	}
}

func TestUniversalBinaryCitationsKeepDistinctPhysicalOffsets(t *testing.T) {
	store, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	hash := caso.Hash([]byte("Mach-O universal de prueba"))
	report := triaje.Binary{SHA256: hash, Format: "Mach-O universal", Size: 0x4000,
		Images: []triaje.BinaryImage{
			{Architecture: "CpuAmd64", Subtype: "0x3", File: triaje.FileRange{Offset: "0x1000", Size: 0x200}},
			{Architecture: "CpuArm64", Subtype: "0x0", File: triaje.FileRange{Offset: "0x3000", Size: 0x200}},
		},
		Sections: []triaje.Section{
			{Name: "__TEXT/__text", Address: "0x1000", Size: 16, File: &triaje.FileRange{Offset: "0x1100", Size: 16}, Image: 1},
			{Name: "__TEXT/__text", Address: "0x1000", Size: 16, File: &triaje.FileRange{Offset: "0x3100", Size: 16}, Image: 2},
		},
		Instructions: []triaje.Instruction{
			{Section: 0, Address: "0x1008", Offset: "0x1108", Bytes: "c3", Text: "ret"},
			{Section: 1, Address: "0x1008", Offset: "0x3108", Bytes: "c0035fd6", Text: "ret"},
			{Section: 1, Address: "0x100f", Offset: "0x310f", Bytes: "c0035fd6", Text: "ret"},
		},
		Symbols: []triaje.Symbol{
			{Name: "entry", Kind: "Externo", Address: "0x1008", Section: "__TEXT/__text", Offset: "0x1108", Image: 1},
			{Name: "entry", Kind: "Externo", Address: "0x1008", Section: "__TEXT/__text", Offset: "0x3108", Image: 2},
		},
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save([]caso.Record{{Kind: "binario", Title: report.Format, SHA256: hash, Time: caso.Now(), Details: string(data)}}); err != nil {
		t.Fatal(err)
	}
	page, err := store.Page(t.Context(), caso.PageRequest{Kind: "binario"})
	if err != nil || len(page.Rows) != 1 {
		t.Fatalf("registros: %+v, %v", page, err)
	}
	id := page.Rows[0].ID
	const host = "127.0.0.1:8443"
	handler := Handler(host, Settings{}, store, testResources)
	for _, kind := range []string{"simbolo", "instruccion"} {
		for index, offset := range []string{"0x1108", "0x3108"} {
			position := strconv.Itoa(index)
			query := "/api/registro/" + id + "/cita-binaria?revision=1&tipo=" + kind + "&indice=" + position
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest("GET", "http://"+host+query, nil))
			expected := analisis.BinaryCitation{Schema: analisis.BinaryCitationSchema, RecordID: id, Revision: 1, SHA256: hash,
				InspectionSHA256: caso.Hash(data), Kind: kind, Index: index, Offset: offset}
			var actual analisis.BinaryCitation
			if err := json.Unmarshal(response.Body.Bytes(), &actual); response.Code != 200 || err != nil || actual != expected {
				t.Fatalf("cita web: %+v, %v, %d", actual, err, response.Code)
			}
			var stdout, stderr bytes.Buffer
			_, err := terminal.Run([]string{"citar-binario", "--id", id, "--revision", "1", "--tipo", kind, "--indice", position},
				&stdout, &stderr, func() (*caso.Store, error) { return store, nil })
			if err != nil {
				t.Fatalf("CLI: %v, %s", err, &stderr)
			}
			actual = analisis.BinaryCitation{}
			if err := json.Unmarshal(stdout.Bytes(), &actual); err != nil || actual != expected {
				t.Fatalf("cita CLI: %+v, %v", actual, err)
			}
		}
	}
	response := httptest.NewRecorder()
	query := "/api/registro/" + id + "/cita-binaria?revision=1&tipo=instruccion&indice=2"
	handler.ServeHTTP(response, httptest.NewRequest("GET", "http://"+host+query, nil))
	if response.Code != 404 {
		t.Fatalf("se citó una instrucción sin respaldo físico completo: %d", response.Code)
	}
}
