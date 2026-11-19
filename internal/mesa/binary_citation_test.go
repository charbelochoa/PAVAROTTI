package mesa

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"pavarotti/internal/analisis"
	"pavarotti/internal/caso"
	"pavarotti/internal/ingesta"
	"pavarotti/internal/terminal"
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
