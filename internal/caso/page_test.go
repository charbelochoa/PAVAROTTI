package caso

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestLocalPageAndSummary(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	testPage(t, store)
}

func TestPostgresPageAndSummary(t *testing.T) {
	dsn := os.Getenv("PAVAROTTI_TEST_POSTGRES")
	if dsn == "" {
		t.Skip("PAVAROTTI_TEST_POSTGRES no configurado")
	}
	expediente := "test-" + hex.EncodeToString(randBytes(t))
	store, err := OpenPostgres(t.Context(), dsn, expediente)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		defer store.Close()
		if _, err := store.db.Exec("DELETE FROM pavarotti_note_revisions WHERE expediente = $1", expediente); err != nil {
			t.Error(err)
		}
		if _, err := store.db.Exec("DELETE FROM pavarotti_evidence_batches WHERE expediente = $1", expediente); err != nil {
			t.Error(err)
		}
	})
	testPage(t, store)
}

func testPage(t *testing.T, store *Store) {
	t.Helper()
	ctx := t.Context()
	entries := make([]Record, 520)
	for index := range entries {
		entries[index] = Record{Kind: "indicador", Time: "2026-11-18T21:00:00Z",
			Title: fmt.Sprintf("Registro %04d", index), Details: "Contenido completo fuera de la lista"}
	}
	entries[0] = Record{Kind: "archivo HAR", Time: "2026-11-18T21:00:00Z", Title: "GET 404",
		Traffic: &Traffic{Method: "GET", Status: 404, Type: "text/html", Millis: 12, Bucket: 16},
		Signals: []string{"Señal del HAR"}, Details: "Detalle que solo se obtiene desde el inspector"}
	if err := store.Save(entries); err != nil {
		t.Fatal(err)
	}
	note := Record{Kind: "nota", Time: "2026-11-18T21:00:00.1Z", Title: "Nota inicial", Details: "original"}
	traffic := Record{Kind: "tráfico", Time: "2026-11-18T21:00:00.01Z", Title: "Respuesta",
		Traffic: &Traffic{Status: 200, Type: "application/json", Bucket: 8}, Signals: []string{"Señal HTTP"}}
	for _, entry := range []Record{note, traffic} {
		if err := store.Save([]Record{entry}); err != nil {
			t.Fatal(err)
		}
	}
	first, err := store.Page(ctx, PageRequest{Limit: 2})
	if err != nil || len(first.Rows) != 2 || first.Rows[0].Kind != "nota" || first.Rows[1].Kind != "tráfico" || first.Next == "" {
		t.Fatalf("primera página: %+v, %v", first, err)
	}
	id := first.Rows[0].ID
	if _, err := store.Edit(id, 1, "REVISIÓN [cita] 100%", "origen", strings.Repeat("á", 720)); err != nil {
		t.Fatal(err)
	}
	found, err := store.Page(ctx, PageRequest{Kind: "nota", Search: "revisión [cita] 100%"})
	if err != nil || len(found.Rows) != 1 || found.Rows[0].ID != id || found.Next != "" {
		t.Fatalf("búsqueda literal de la revisión vigente: %+v, %v", found, err)
	}
	note, err = store.Record(ctx, id)
	if err != nil || note.Revision != 2 || note.Title != "REVISIÓN [cita] 100%" || len(note.Details) != 1440 {
		t.Fatalf("inspector: revisión %d, %v", note.Revision, err)
	}
	for _, expected := range []struct {
		revision int
		title    string
	}{{1, "Nota inicial"}, {2, "REVISIÓN [cita] 100%"}} {
		cited, err := store.RecordRevision(ctx, id, expected.revision)
		if err != nil || cited.Revision != expected.revision || cited.Title != expected.title || cited.ID != id {
			t.Fatalf("cita histórica: %+v, %v", cited, err)
		}
	}
	if _, err := store.RecordRevision(ctx, id, 3); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revisión inexistente: %v", err)
	}
	httpPage, err := store.Page(ctx, PageRequest{Kind: "http"})
	if err != nil || len(httpPage.Rows) != 2 || httpPage.Rows[0].Kind != "tráfico" || httpPage.Rows[1].Kind != "archivo HAR" {
		t.Fatalf("historial HTTP: %+v, %v", httpPage, err)
	}
	httpPage, err = store.Page(ctx, PageRequest{Kind: "http", HTTPClass: 4})
	if err != nil || len(httpPage.Rows) != 1 || httpPage.Rows[0].Traffic == nil ||
		httpPage.Rows[0].Traffic.Status != 404 || httpPage.Rows[0].Traffic.Millis != 12 || httpPage.Rows[0].SignalCount != 1 {
		t.Fatalf("filtro por clase de estado: %+v, %v", httpPage, err)
	}
	httpPage, err = store.Page(ctx, PageRequest{Kind: "http", HTTPClass: 4, HTTPSource: "archivo HAR", HTTPMethod: "GET",
		HTTPFrom: "2026-11-18", HTTPTo: "2026-11-18", Search: "Señal del HAR"})
	if err != nil || len(httpPage.Rows) != 1 || httpPage.Rows[0].Kind != "archivo HAR" {
		t.Fatalf("filtros HTTP combinados: %+v, %v", httpPage, err)
	}
	for _, noMatch := range []PageRequest{
		{Kind: "http", HTTPSource: "tráfico", HTTPMethod: "GET"},
		{Kind: "http", HTTPSource: "archivo HAR", HTTPMethod: "POST"},
		{Kind: "http", HTTPFrom: "2026-11-19"},
		{Kind: "http", HTTPTo: "2026-11-17"},
	} {
		page, err := store.Page(ctx, noMatch)
		if err != nil || len(page.Rows) != 0 {
			t.Fatalf("filtro HTTP %+v: %+v, %v", noMatch, page, err)
		}
	}
	for _, invalid := range []PageRequest{
		{Kind: "nota", HTTPSource: "archivo HAR"},
		{Kind: "http", HTTPSource: "desconocido"},
		{Kind: "http", HTTPMethod: "DESCONOCIDO"},
		{Kind: "http", HTTPFrom: "2026-02-30"},
		{Kind: "http", HTTPFrom: "2026-11-18", HTTPTo: "2026-11-17"},
	} {
		if _, err := store.Page(ctx, invalid); !errors.Is(err, ErrInvalidPage) {
			t.Fatalf("filtro HTTP inválido %+v: %v", invalid, err)
		}
	}
	if _, err := store.Record(ctx, strings.Repeat("a", 64)+"-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("registro inexistente: %v", err)
	}
	if _, err := store.Page(ctx, PageRequest{After: "cursor-invalido"}); !errors.Is(err, ErrInvalidPage) {
		t.Fatalf("cursor inválido: %v", err)
	}
	seen := map[string]bool{first.Rows[0].ID: true, first.Rows[1].ID: true}
	for cursor := first.Next; cursor != ""; {
		page, err := store.Page(ctx, PageRequest{Limit: 53, After: cursor})
		if err != nil || len(page.Rows) == 0 || len(page.Rows) > 53 {
			t.Fatalf("página inválida: %d, %v", len(page.Rows), err)
		}
		for _, row := range page.Rows {
			if seen[row.ID] {
				t.Fatalf("registro repetido: %s", row.ID)
			}
			seen[row.ID] = true
		}
		cursor = page.Next
	}
	summary, err := store.Summary(ctx)
	if err != nil || len(seen) != 522 || summary.Total != 522 || summary.Traffic != 2 || summary.Signals != 2 ||
		summary.Status["200"] != 1 || summary.Status["404"] != 1 || summary.MIME["application/json"] != 1 || summary.Bucket["8"] != 1 {
		t.Fatalf("cobertura del expediente: %d, %+v, %v", len(seen), summary, err)
	}
}
