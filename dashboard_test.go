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
