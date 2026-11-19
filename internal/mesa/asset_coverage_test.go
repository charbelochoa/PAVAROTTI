package mesa

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"testing"

	"pavarotti/internal/analisis"
	"pavarotti/internal/caso"
	"pavarotti/internal/terminal"
)

func TestAssetCoverageMatchesTerminalAndEvidenceRoutes(t *testing.T) {
	store, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	const stamp = "2026-11-07T12:00:00Z"
	if err := store.Save([]caso.Record{
		{Kind: "stix", Network: "192.0.2.0/24", Time: stamp, Title: "Red registrada"},
		{Kind: "dns", Source: "host.invalid, 192.0.2.9", Title: "A host.invalid", SourceID: "1/respuesta/1", Time: stamp},
	}); err != nil {
		t.Fatal(err)
	}
	const host = "127.0.0.1:8443"
	handler := Handler(host, Settings{}, store, testResources)
	get := func(path string, status int) []byte {
		t.Helper()
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest("GET", "http://"+host+path, nil))
		if response.Code != status {
			t.Fatalf("%s: %d, esperado %d, respuesta %s", path, response.Code, status, response.Body)
		}
		return response.Body.Bytes()
	}
	web := get("/api/activos/cobertura?tipo=red&valor=192.0.2.5%2F24&desde=2026-11-07&hasta=2026-11-07", 200)
	get("/api/activos/cobertura?tipo=red&valor=192.0.2.0%2F24&desde=2026-11-08&hasta=2026-11-07", 400)
	var fromWeb analisis.AssetCoverageReport
	if err := json.Unmarshal(web, &fromWeb); err != nil || fromWeb.Criteria.Value != "192.0.2.0/24" ||
		len(fromWeb.Members) != 1 || len(fromWeb.Sources) != 1 || len(fromWeb.Members[0].Evidence) != 1 {
		t.Fatalf("informe: %+v, %v", fromWeb, err)
	}
	ref := fromWeb.Members[0].Evidence[0]
	var record caso.Record
	if err := json.Unmarshal(get("/api/registro/"+ref.ID+"?revision=1", 200), &record); err != nil ||
		record.Title != ref.Title || record.Revision != ref.Revision {
		t.Fatalf("evidencia: %+v, %v", record, err)
	}

	var stdout, stderr bytes.Buffer
	handled, err := terminal.Run([]string{"cobertura-activo", "--tipo", "red", "--valor", "192.0.2.0/24", "--desde", "2026-11-07", "--hasta", "2026-11-07"},
		&stdout, &stderr, func() (*caso.Store, error) { return store, nil })
	if !handled || err != nil {
		t.Fatalf("CLI: %v, %s", err, &stderr)
	}
	var fromCLI analisis.AssetCoverageReport
	if err := json.Unmarshal(stdout.Bytes(), &fromCLI); err != nil || !reflect.DeepEqual(fromCLI, fromWeb) {
		t.Fatalf("informe CLI: %+v, %v", fromCLI, err)
	}
}
