package caso

import (
	"reflect"
	"strings"
	"testing"
)

func TestLocalTextIndexKeepsLiteralSearchAndCurrentNotes(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	const stamp = "2026-11-19T00:00:00Z"
	if err := store.Save([]Record{
		{Kind: "nota", Title: "Título anterior", Source: "Origen previo", Details: "Primera revisión", Time: stamp},
		{Kind: "binario", Title: "Bloque", Source: "Siguiente", Details: strings.Repeat("d", maxLocalSearchText) + "Marca al final", Time: stamp},
		{Kind: "dependencias", Title: "paquetes", Time: stamp, Dependencies: &DependencyInventory{Entries: []Dependency{
			{Name: "@demo/paquete", Version: "7.10.2", InstalledAs: "ruta/Paquete", Replacement: &Replacement{Name: "Alternativa 100%_literal"}},
		}}},
		{Kind: "archivo HAR", Title: "Estado probado", Source: "https://192.0.2.2", Time: stamp,
			Traffic: &Traffic{Status: 204, Method: "GET"}, Signals: []string{"Señal previa"}},
	}); err != nil {
		t.Fatal(err)
	}
	check := func(query PageRequest, count int) Page {
		t.Helper()
		query.Limit = 5
		want, err := store.localPage(t.Context(), query, pageCursor{}, query.Limit+1)
		if err != nil {
			t.Fatal(err)
		}
		page, err := store.Page(t.Context(), query)
		if err != nil || len(page.Rows) != count || !reflect.DeepEqual(page.Rows, want) {
			t.Fatalf("%q: búsqueda indexada %+v, recorrido %+v, error %v", query.Search, page, want, err)
		}
		return page
	}
	note := check(PageRequest{Search: "Título anterior"}, 1).Rows[0].ID
	check(PageRequest{Search: note}, 1)
	check(PageRequest{Search: note[61:]}, 1)
	for _, item := range []struct {
		query string
		count int
	}{{"marca al final", 1}, {"BLOQUESIGUIENTE", 0}, {"7.10.2", 1}, {"ruta/paquete", 1}, {"100%_literal", 1},
		{"Señal previa", 1}, {"204", 1}} {
		check(PageRequest{Search: item.query}, item.count)
	}
	check(PageRequest{Search: "GET", Kind: "http", HTTPClass: 2}, 1)
	if _, err := store.Edit(note, 1, "Título vigente", "", "Segunda revisión"); err != nil {
		t.Fatal(err)
	}
	check(PageRequest{Search: "Título anterior"}, 0)
	check(PageRequest{Search: "Origen previo"}, 0)
	check(PageRequest{Search: "Título vigente"}, 1)
	cited, err := store.RecordRevision(t.Context(), note, 1)
	if err != nil || cited.Title != "Título anterior" {
		t.Fatalf("revisión anterior: %+v, %v", cited, err)
	}
}
