package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pavarotti/internal/caso"
)

func TestTerminalExpediente(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "expediente")
	capture := filepath.Join(root, "captura.har")
	data := []byte(`{"log":{"entries":[{"time":31,"request":{"method":"GET","url":"https://example.com/secreto?token=x"},"response":{"status":200,"headers":[{"name":"content-type","value":"text/html; charset=UTF-8"}]}}]}}`)
	if err := os.WriteFile(capture, data, 0600); err != nil {
		t.Fatal(err)
	}
	open := func() (*caso.Store, error) { return caso.Open(directory) }
	call := func(args ...string) string {
		t.Helper()
		var out, stderr bytes.Buffer
		handled, err := terminal(args, &out, &stderr, open)
		if !handled || err != nil {
			t.Fatalf("terminal %v: handled=%t err=%v stderr=%s", args, handled, err, stderr.String())
		}
		return out.String()
	}
	call("importar", "har", capture)
	call("importar", "har", capture)
	call("nota", "--titulo", "=1+2", "--texto", "observación del analista")
	var filtered []caso.Record
	result := call("listar", "--tipo", "har", "--buscar", "example.com", "--json")
	if err := json.Unmarshal([]byte(result), &filtered); err != nil || len(filtered) != 1 ||
		filtered[0].Source != "https://example.com" || filtered[0].SHA256 != caso.Hash(data) {
		t.Fatalf("respuesta filtrada: %s (%v)", result, err)
	}
	if strings.Contains(result, "token=") || strings.Contains(result, "/secreto") {
		t.Fatalf("se incluyó una parte privada de la URL: %s", result)
	}
	export := call("exportar", "--formato", "csv", "--tipo", "nota")
	rows, err := csv.NewReader(strings.NewReader(export)).ReadAll()
	if err != nil || len(rows) != 2 || rows[1][3] != "'=1+2" {
		t.Fatalf("CSV: %q (%v)", export, err)
	}
}

func TestTerminalArchivoExportadoNoSeSobrescribe(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "exportacion.json")
	original := []byte("exportación anterior")
	if err := os.WriteFile(output, original, 0600); err != nil {
		t.Fatal(err)
	}
	open := func() (*caso.Store, error) { return caso.Open(filepath.Join(root, "expediente")) }
	handled, err := terminal([]string{"exportar", "--salida", output}, &bytes.Buffer{}, &bytes.Buffer{}, open)
	if !handled || err == nil {
		t.Fatalf("exportación sobre un archivo existente: handled=%t err=%v", handled, err)
	}
	data, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(data, original) {
		t.Fatalf("contenido original: %q (%v)", data, err)
	}
}
