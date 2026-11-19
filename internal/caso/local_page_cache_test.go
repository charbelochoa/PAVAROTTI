package caso

import (
	"reflect"
	"strings"
	"testing"
)

func TestLocalPageIndexMatchesScanAcrossBatches(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	const stamp = "2026-11-19T00:00:00.123456789Z"
	sample := Record{
		Kind: "archivo HAR", Title: "GET 204", Time: stamp, Source: "https://192.0.2.1",
		Traffic:      &Traffic{Method: "GET", Status: 204},
		Signals:      []string{"Señal de prueba"},
		HTTPFindings: []HTTPFinding{{Rule: "hsts-ausente"}},
	}
	batch := []Record{{Kind: "nota", Title: "Anterior", Time: stamp, Details: "Primera revisión"}}
	for range 12 {
		batch = append(batch, sample)
	}
	for _, group := range [][]Record{
		{sample, {Kind: "binario", Time: stamp, Title: "ELF", SourceID: "muestra.bin"}},
		batch,
	} {
		if err := store.Save(group); err != nil {
			t.Fatal(err)
		}
	}
	check := func(query PageRequest) {
		t.Helper()
		for {
			after, err := decodeCursor(query.After)
			if err != nil {
				t.Fatal(err)
			}
			fromScan, err := store.localPage(t.Context(), query, after, query.Limit+1)
			if err != nil {
				t.Fatal(err)
			}
			page, err := store.Page(t.Context(), query)
			if err != nil || !reflect.DeepEqual(page.Rows, fromScan[:min(len(fromScan), query.Limit)]) {
				t.Fatalf("índice y recorrido: %+v, %+v, %v", page.Rows, fromScan, err)
			}
			if page.Next == "" {
				break
			}
			if page.Next == query.After {
				t.Fatal("el cursor se repitió")
			}
			query.After = page.Next
		}
	}
	check(PageRequest{Limit: 2})
	check(PageRequest{Limit: 1, Kind: "binario"})
	check(PageRequest{Limit: 1, Kind: "http", HTTPClass: 2, HTTPRule: "hsts-ausente", HTTPFrom: "2026-11-19"})
	note, err := store.Page(t.Context(), PageRequest{Kind: "nota"})
	if err != nil || len(note.Rows) != 1 {
		t.Fatalf("nota: %+v, %v", note, err)
	}
	if _, err := store.Edit(note.Rows[0].ID, 1, "Vigente", "Referencia", strings.Repeat("a", 400)); err != nil {
		t.Fatal(err)
	}
	sample.Time, sample.Title = "2026-11-20T00:00:00Z", "Nuevo lote"
	if err := store.Save([]Record{sample}); err != nil {
		t.Fatal(err)
	}
	check(PageRequest{Limit: 2})
	page, err := store.Page(t.Context(), PageRequest{Kind: "http", Limit: 1})
	if err != nil || len(page.Rows) != 1 || page.Rows[0].Title != "Nuevo lote" || page.Rows[0].Traffic == nil {
		t.Fatalf("lote nuevo: %+v, %v", page, err)
	}
	page.Rows[0].Traffic.Status = 100
	again, err := store.Page(t.Context(), PageRequest{Kind: "http", Limit: 1})
	if err != nil || !reflect.DeepEqual(again.Rows[0].Traffic, sample.Traffic) {
		t.Fatalf("caché alterada por el lector: %+v, %v", again, err)
	}
}
