package mesa

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"pavarotti/internal/caso"
)

func TestDirectoryUploadRejectsInvalidPathsBeforeSaving(t *testing.T) {
	store, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const host = "127.0.0.1:7000"
	var body bytes.Buffer
	parts := multipart.NewWriter(&body)
	for _, path := range []string{"src/valido.go", "../rechazado.go"} {
		part, err := parts.CreateFormFile(url.PathEscape(path), "fuente.go")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(part, "package fixture\n"); err != nil {
			t.Fatal(err)
		}
	}
	if err := parts.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "http://"+host+"/api/revision/directorio", &body)
	r.Header.Set("Content-Type", parts.FormDataContentType())
	r.Header.Set("Origin", "http://"+host)
	w := httptest.NewRecorder()
	Handler(host, Settings{}, store, testResources).ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("respuesta: %d, %s", w.Code, w.Body.String())
	}
	rows, err := store.Records()
	if err != nil || len(rows) != 0 {
		t.Fatalf("guardado parcial: %d, %v", len(rows), err)
	}
}
