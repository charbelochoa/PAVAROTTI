package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"pavarotti/internal/caso"
	"pavarotti/internal/trafico"
	"pavarotti/internal/triaje"
)

func TestExpediente(t *testing.T) {
	const host = "127.0.0.1:7000"
	const report = `[{"id":4,"name":"Revisión de acceso","evidence":"Cabecera revisada"}]`
	const har = `{"log":{"entries":[{"time":12,"request":{"method":"GET","url":"https://example.invalid/private?token=omit-this"},"response":{"status":200,"headers":[{"name":"Content-Type","value":"text/html; charset=utf-8"},{"name":"Set-Cookie","value":"session=omit-this"}]}}]}}`
	dir := t.TempDir()
	store, err := caso.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	app := dashboard(host, settings{Version: version}, store)
	call := func(method, path, origin, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, "http://"+host+path, strings.NewReader(body))
		request.Header.Set("Origin", origin)
		response := httptest.NewRecorder()
		app.ServeHTTP(response, request)
		return response
	}
	for _, path := range []string{"/", "/app.js", "/mascara.svg", "/credits.json"} {
		if got := call("GET", path, "", "").Code; got != 200 {
			t.Fatalf("%s: %d", path, got)
		}
	}
	if got := call("POST", "/api/archivo/hallazgos", "http://wrong.invalid", report).Code; got != 403 {
		t.Fatalf("origen ajeno: %d", got)
	}
	for _, input := range []struct{ kind, data string }{{"hallazgos", report}, {"hallazgos", report}, {"har", har}} {
		if response := call("POST", "/api/archivo/"+input.kind, "http://"+host, input.data); response.Code != 200 {
			t.Fatal(response.Body.String())
		}
	}
	reopened, err := caso.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	records, err := reopened.Records()
	if err != nil || len(records) != 2 {
		t.Fatalf("registros persistentes: %v, %v", records, err)
	}
	raw := call("GET", "/api/registro", "", "").Body.String()
	if strings.Contains(raw, "omit-this") || strings.Contains(raw, "/private") ||
		!strings.Contains(raw, caso.Hash([]byte(report))) || !strings.Contains(raw, "nosniff") {
		t.Fatalf("metadatos del expediente: %s", raw)
	}
}

func TestProxyObservaDestinoConfigurado(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "http://"+r.Host+"/ready", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Set-Cookie", "session=omit-this")
		_, _ = io.WriteString(w, "respuesta del laboratorio")
	}))
	defer upstream.Close()
	target, err := trafico.Target(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	store, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const host = "127.0.0.1:7001"
	handler := trafico.Reverse(target, host, store)
	for _, path := range []string{"/ready?auth=omit-this", "/redirect"} {
		request := httptest.NewRequest("GET", path, nil)
		request.Host = host
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if path == "/redirect" {
			if response.Code != 302 || response.Header().Get("Location") != "http://"+host+"/ready" {
				t.Fatalf("redirección: %v", response.Result())
			}
		} else if response.Code != 200 || response.Body.String() != "respuesta del laboratorio" {
			t.Fatalf("respuesta: %d %s", response.Code, response.Body)
		}
	}
	records, err := store.Records()
	if err != nil || len(records) != 2 {
		t.Fatalf("registros: %v, %v", records, err)
	}
	for _, record := range records {
		if record.Source != upstream.URL || record.Traffic.Type != "text/plain" && record.Traffic.Type != "text/html" {
			t.Fatalf("registro: %v", record)
		}
		raw, _ := json.Marshal(record)
		if strings.Contains(string(raw), "omit-this") {
			t.Fatalf("dato sensible persistido: %s", raw)
		}
	}
}

func TestProxyDistingueFalloDeConexionDeCabeceras(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	target, err := trafico.Target(upstream.URL)
	upstream.Close()
	if err != nil {
		t.Fatal(err)
	}
	store, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const host = "127.0.0.1:7001"
	handler := trafico.Reverse(target, host, store)
	request := httptest.NewRequest("GET", "/", nil)
	request.Host = host
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	records, err := store.Records()
	if response.Code != 502 || err != nil || len(records) != 1 {
		t.Fatalf("resultado: %d, %v, %v", response.Code, records, err)
	}
	if len(records[0].Signals) != 1 || records[0].Signals[0] != "El proxy no recibió respuesta del destino" {
		t.Fatalf("señales incorrectas: %v", records[0].Signals)
	}
}

func TestEdicionAnalisisYRevision(t *testing.T) {
	const host = "127.0.0.1:7000"
	store, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	app := dashboard(host, settings{}, store)
	call := func(method, path, body string, expected int) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, "http://"+host+path, strings.NewReader(body))
		req.Header.Set("Origin", "http://"+host)
		rec := httptest.NewRecorder()
		app.ServeHTTP(rec, req)
		if rec.Code != expected {
			t.Fatalf("%s %s: %d, esperado %d · %s", method, path, rec.Code, expected, rec.Body)
		}
		return rec
	}
	call("POST", "/api/nota", `{"title":"Inspección","details":"Una revisión","source":"https://example.invalid"}`, 200)
	var records []caso.Record
	if err := json.Unmarshal(call("GET", "/api/registro", "", 200).Body.Bytes(), &records); err != nil || len(records) != 1 {
		t.Fatalf("registro: %v, %v", records, err)
	}
	path := "/api/nota/" + records[0].ID
	body := `{"title":"Inspección manual","details":"La segunda revisión","source":"https://example.invalid","revision":1}`
	call("PATCH", path, body, 200)
	call("PATCH", path, body, 409)
	history := call("GET", path+"/historial", "", 200).Body.String()
	if !strings.Contains(history, "Una revisión") || strings.Contains(history, "segunda revisión") {
		t.Fatal(history)
	}
	page := call("GET", "/api/registro/pagina?buscar=segunda+revisi%C3%B3n", "", 200).Body.String()
	if !strings.Contains(page, records[0].ID) || strings.Contains(page, "segunda revisión") {
		t.Fatalf("la lista debe encontrar el registro sin incluir su detalle: %s", page)
	}
	detail := call("GET", "/api/registro/"+records[0].ID, "", 200).Body.String()
	if !strings.Contains(detail, "segunda revisión") {
		t.Fatal(detail)
	}
	cited := call("GET", "/api/registro/"+records[0].ID+"?revision=1", "", 200).Body.String()
	if !strings.Contains(cited, "Una revisión") || strings.Contains(cited, "segunda revisión") {
		t.Fatal(cited)
	}
	call("GET", "/api/registro/"+records[0].ID+"?revision=3", "", 404)
	call("GET", "/api/registro/"+records[0].ID+"?revision=-1", "", 400)
	call("GET", "/api/registro/pagina?limite=101", "", 400)
	call("GET", "/api/registro/pagina?despues=invalido", "", 400)
	code := "package demo\nimport \"net/http\"\nfunc check() { http.Get(\"https://example.invalid\") }"
	call("POST", "/api/archivo/codigo", code, 200)
	dns := `{"Status":0,"Answer":[{"name":"example.invalid.","type":1,"TTL":120,"data":"192.0.2.17"}]}`
	call("POST", "/api/archivo/dns", dns, 200)
	dnsPage := call("GET", "/api/registro/pagina?tipo=dns&buscar=192.0.2.17", "", 200).Body.String()
	if !strings.Contains(dnsPage, "A example.invalid") {
		t.Fatal(dnsPage)
	}
	call("POST", "/api/analisis/tareas", `{"priority":1}`, 409)
	data := call("POST", "/api/analisis", "", 200).Body.String()
	if !strings.Contains(data, "example.invalid") || !strings.Contains(data, records[0].ID) || !strings.Contains(data, "192.0.2.17") {
		t.Fatal(data)
	}
}

func TestInspeccionBinario(t *testing.T) {
	file, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	result := triaje.Inspect(data)
	if result.SHA256 != caso.Hash(data) || len(result.Sections) == 0 {
		t.Fatal(fmt.Sprintf("resultado inválido: %v", result))
	}
	if _, err := trafico.Target((&url.URL{Scheme: "file", Path: "/example"}).String()); err == nil {
		t.Fatal("destino ajeno a HTTP aceptado")
	}
}
