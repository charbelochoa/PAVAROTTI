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
	"pavarotti/internal/ingesta"
	"pavarotti/internal/terminal"
)

func TestAssetRelationsMatchCLIAndOpenOriginalEvidence(t *testing.T) {
	store, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	raw := `{"Status":0,"Answer":[{"name":"_sip._tcp.portal.invalid.","type":33,"data":"1 10 5060 servicio.invalid."}]}`
	records, err := ingesta.ParseNamed("dns", strings.NewReader(raw), "captura.json")
	if err != nil {
		t.Fatal(err)
	}
	records[0].Time = "2026-06-01T11:05:03Z"
	if err := store.Save(records); err != nil {
		t.Fatal(err)
	}
	const host = "127.0.0.1:8443"
	handler := Handler(host, Settings{}, store, testResources)
	call := func(path string, status int) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest("GET", "http://"+host+path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != status {
			t.Fatalf("GET %s: %d, %s", path, response.Code, response.Body)
		}
		return response
	}
	query := url.Values{"tipo": {"dominio"}, "valor": {"_SIP._TCP.PORTAL.INVALID."}, "desde": {"2026-06-01"}, "hasta": {"2026-06-01"}}
	web := call("/api/activos/relaciones?"+query.Encode(), 200)
	var related, fromCLI analisis.AssetRelationsReport
	if err := json.Unmarshal(web.Body.Bytes(), &related); err != nil || len(related.Rows) != 1 || related.Records != 1 ||
		related.Rows[0].Value != "servicio.invalid" || related.Rows[0].Kind != "dns-srv" {
		t.Fatalf("resultado web: %+v, %v", related, err)
	}
	var stdout, stderr bytes.Buffer
	_, err = terminal.Run([]string{"relaciones-activo", "--tipo", "dominio", "--valor", "_SIP._TCP.PORTAL.INVALID.",
		"--desde", "2026-06-01", "--hasta", "2026-06-01"}, &stdout, &stderr, func() (*caso.Store, error) { return store, nil })
	if err != nil {
		t.Fatalf("CLI: %v, %s", err, &stderr)
	}
	if err := json.Unmarshal(stdout.Bytes(), &fromCLI); err != nil || !reflect.DeepEqual(related, fromCLI) {
		t.Fatalf("resultado CLI: %+v, %v", fromCLI, err)
	}
	ref := related.Rows[0].Sources[0]
	record := call("/api/registro/"+ref.ID+"?revision=1", 200)
	if !strings.Contains(record.Body.String(), "SRV _sip._tcp.portal.invalid") || ref.Revision != 1 {
		t.Fatalf("cita: %+v, %s", ref, record.Body)
	}
	call("/api/activos/ficha?tipo=dominio&valor=servicio.invalid", 200)
	query.Del("hasta")
	call("/api/activos/relaciones?"+query.Encode(), 400)
}
