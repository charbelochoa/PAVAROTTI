package trafico

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"pavarotti/internal/caso"
)

func TestPassiveSignalsDistinguishHeaderEvidence(t *testing.T) {
	const source = "https://evidence.invalid"
	for _, fixture := range []struct {
		name, method string
		status       int
		headers      http.Header
		want         []string
	}{
		{"HTML con políticas débiles", "GET", 200, http.Header{
			"Content-Type":                        {"text/html; charset=utf-8"},
			"Content-Security-Policy-Report-Only": {"frame-ancestors 'none'"},
			"Referrer-Policy":                     {"strict-origin", "unsupported, unsafe-url"}, "Strict-Transport-Security": {"max-age=0"},
		}, []string{"nosniff-ausente", "marcos-sin-politica", "referencia-unsafe-url", "hsts-inactiva"}},
		{"HTML con políticas declaradas", "GET", 200, http.Header{
			"Content-Type": {"application/xhtml+xml"}, "X-Content-Type-Options": {"NOSNIFF"},
			"Content-Security-Policy": {"default-src 'self'; Frame-Ancestors\t'none'"},
			"Referrer-Policy":         {"unsafe-url, no-referrer"}, "Strict-Transport-Security": {`max-age="31000000"; includeSubDomains`},
		}, nil},
		{"redirección HTTP observada", "GET", 302, http.Header{
			"Location":                  {"http://destination.invalid/path?token=synthetic-secret"},
			"Strict-Transport-Security": {"max-age=3; max-age=5"},
		}, []string{"hsts-invalida", "redireccion-http"}},
		{"redirección relativa", "GET", 302, http.Header{"Location": {"/private"}}, []string{"hsts-ausente"}},
		{"respuesta intermedia", "GET", 103, http.Header{}, nil},
		{"sin respuesta", "GET", 502, nil, nil},
		{"HEAD", "HEAD", 200, http.Header{"Strict-Transport-Security": {"max-age=3"}}, nil},
		{"reset content", "GET", 205, http.Header{"Strict-Transport-Security": {"max-age=3"}}, nil},
		{"formato MIME inválido", "GET", 200, http.Header{"Content-Type": {"html"}}, []string{"mime-ausente", "hsts-ausente"}},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			observed := Observe(source, fixture.method, fixture.status, 12*time.Millisecond, fixture.headers)
			assertPassiveRules(t, observed, fixture.want)
			encoded, err := json.Marshal(observed)
			if err != nil || strings.Contains(string(encoded), "synthetic-secret") || strings.Contains(string(encoded), "/private") {
				t.Fatalf("contenido conservado: %s, %v", encoded, err)
			}
		})
	}
}

func TestPassiveHARKeepsCookieValuesAndLocationsPrivate(t *testing.T) {
	const har = `{"log":{"entries":[
		{"startedDateTime":"2020-01-02T08:00:00-06:00","time":14,"request":{"method":"GET","url":"https://example.invalid/private?token=fixture-token"},
		"response":{"status":200,"headers":[{"name":"content-type","value":"application/json; charset=utf-8"},
		{"name":"set-cookie","value":"fixture-name=fixture-token; SameSite=None; Expires=Fri, 03 Jan 2020 00:00:00 GMT"},
		{"name":"Set-Cookie","value":"fixture-safe=fixture-token; Secure"},
		{"name":"Set-Cookie","value":"fixture-expired=fixture-token; Expires=Wed, 01 Jan 2020 00:00:00 GMT"},
		{"name":"Set-Cookie","value":"fixture-deleted=fixture-token; Max-Age=0"}]}}
	]}}`
	records, err := ImportHAR([]byte(har))
	if err != nil || len(records) != 1 {
		t.Fatalf("HAR: %d, %v", len(records), err)
	}
	entry := records[0]
	assertPassiveRules(t, entry, []string{"hsts-ausente", "cookie-sin-secure", "cookie-none-sin-secure"})
	if entry.Source != "https://example.invalid" || entry.SourceID != "1" || entry.Time != "2020-01-02T14:00:00Z" ||
		entry.SHA256 != caso.Hash([]byte(har)) || entry.HTTPFindings[1].Observation != "Falta Secure en 1 de 2 cookies analizadas." {
		t.Fatalf("procedencia y recuento: %+v", entry)
	}
	encoded, err := json.Marshal(entry)
	if err != nil || strings.Contains(string(encoded), "fixture-") || strings.Contains(string(encoded), "/private") {
		t.Fatalf("contenido conservado: %s, %v", encoded, err)
	}
}

func assertPassiveRules(t *testing.T, entry caso.Record, want []string) {
	t.Helper()
	var actual, labels []string
	for _, finding := range entry.HTTPFindings {
		if finding.Observation == "" || finding.Header == "" || finding.Label == "" {
			t.Fatalf("evidencia incompleta: %+v", finding)
		}
		actual, labels = append(actual, finding.Rule), append(labels, finding.Label)
	}
	if !slices.Equal(actual, want) || !slices.Equal(labels, entry.Signals) {
		t.Fatalf("reglas %v, se esperaba %v, etiquetas %v", actual, want, entry.Signals)
	}
}
