package mesa

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"pavarotti/internal/analisis"
	"pavarotti/internal/caso"
	"pavarotti/internal/terminal"
)

func TestWatchlistsUseSameEvidenceInMesaAndTerminal(t *testing.T) {
	store, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Save([]caso.Record{{Kind: "dns", Title: "A servicio.invalid", Source: "servicio.invalid, 192.0.2.8"}}); err != nil {
		t.Fatal(err)
	}
	const host = "127.0.0.1:8443"
	const name = "Investigación de guardia"
	path := "/api/seguimiento/" + url.PathEscape(name)
	handler := Handler(host, Settings{}, store, testResources)
	call := func(method, path, payload string, status int) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, "http://"+host+path, strings.NewReader(payload))
		request.Header.Set("Origin", "http://"+host)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != status {
			t.Fatalf("%s %s: %d, %s", method, path, response.Code, response.Body)
		}
		return response
	}
	call("PUT", path, "", 200)
	call("PUT", path+"/activo", `{"type":"dominio","value":" SERVICIO.invalid. "}`, 200)
	call("PUT", path+"/activo", `{"type":"dominio","value":"servicio.invalid"}{}`, 400)
	var stdout, stderr bytes.Buffer
	run := func(args ...string) []byte {
		t.Helper()
		stdout.Reset()
		stderr.Reset()
		_, err := terminal.Run(append([]string{"seguimiento"}, args...), &stdout, &stderr, func() (*caso.Store, error) {
			return store, nil
		})
		if err != nil {
			t.Fatalf("CLI: %v, %s", err, &stderr)
		}
		return stdout.Bytes()
	}
	run("agregar", "--lista", name, "--tipo", "ipv4", "--valor", "192.0.2.99")
	var fromWeb, fromCLI analisis.WatchlistReview
	response := call("GET", path, "", 200)
	if err := json.Unmarshal(response.Body.Bytes(), &fromWeb); err != nil || len(fromWeb.Rows) != 2 ||
		fromWeb.Rows[0].Latest == nil || fromWeb.Rows[0].Latest.Revision != 1 || fromWeb.Rows[1].Latest != nil {
		t.Fatalf("lista web: %+v, %v", fromWeb, err)
	}
	if err := json.Unmarshal(run("listar", "--lista", name, "--json"), &fromCLI); err != nil || !reflect.DeepEqual(fromCLI, fromWeb) {
		t.Fatalf("lista CLI: %+v, %v", fromCLI, err)
	}
	record := call("GET", "/api/registro/"+fromWeb.Rows[0].Latest.ID+"?revision=1", "", 200)
	if !strings.Contains(record.Body.String(), "A servicio.invalid") {
		t.Fatalf("evidencia citada: %s", record.Body)
	}
	call("DELETE", path+"/activo", `{"type":"dominio","value":"servicio.invalid"}`, 200)
	call("DELETE", path, "", 200)
	call("GET", path, "", 404)
	call("GET", "/api/registro/"+fromWeb.Rows[0].Latest.ID+"?revision=1", "", 200)
}
