package caso

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestPostgresSearchProjectionKeepsLegacyMatches(t *testing.T) {
	store, destination := openAuditTest(t), openAuditTest(t)
	ctx := t.Context()
	const stamp = "2026-11-19T01:00:00Z"
	batch := []Record{
		{Kind: "nota", Title: "Título anterior", Source: "Origen anterior", Details: "Texto inicial", Time: stamp},
		{Kind: "binario", Title: "Binario %_ literal", SourceID: "archivo.bin", Time: stamp,
			Details: strings.Repeat("x", 18000) + " marcador final"},
		{Kind: "indicador", Title: "Binario XY literal", Time: stamp},
		{Kind: "dependencias", Title: "Paquetes", Time: stamp, Dependencies: &DependencyInventory{
			Entries: []Dependency{{Name: "@demo/paquete", Version: "3.1.0", InstalledAs: "ruta/modulo",
				Replacement: &Replacement{Name: "Alternativa & interna", Version: "4.0.0"}}}}},
		{Kind: "archivo HAR", Title: "Solicitud", Time: stamp, Source: "https://192.0.2.2",
			Traffic: &Traffic{Method: "GET", Status: 204}, Signals: []string{"Cabecera de prueba"},
			HTTPFindings: []HTTPFinding{{Rule: "hsts-ausente"}}},
	}
	if err := store.Save(batch); err != nil {
		t.Fatal(err)
	}
	check := func(query PageRequest, count int) Page {
		t.Helper()
		query.Limit = 25
		indexed, err := store.Page(ctx, query)
		if err != nil {
			t.Fatal(err)
		}
		scanned, err := store.postgresPageScan(ctx, query, pageCursor{}, query.Limit+1)
		if err != nil || len(indexed.Rows) != count || !reflect.DeepEqual(indexed.Rows, scanned) {
			t.Fatalf("%q: índice %+v, recorrido %+v, %v", query.Search, indexed.Rows, scanned, err)
		}
		return indexed
	}
	note := check(PageRequest{Search: "TÍTULO ANTERIOR"}, 1).Rows[0].ID
	for _, search := range []string{"%_", "archivo.bin", "marcador final", "@demo/paquete", "ruta/modulo",
		"alternativa & interna", "4.0.0", `"cabecera de prueba"`, "binario" + string(rune(31)) + stamp} {
		check(PageRequest{Search: search}, 1)
	}
	check(PageRequest{Kind: "http", Search: "192.0.2.2", HTTPClass: 2, HTTPRule: "hsts-ausente"}, 1)
	if _, err := store.Edit(note, 1, "Título vigente", "", "Texto definitivo"); err != nil {
		t.Fatal(err)
	}
	check(PageRequest{Search: "Origen anterior"}, 0)
	check(PageRequest{Search: "Título anterior"}, 0)
	current := check(PageRequest{Search: "Título vigente"}, 1)

	var backup bytes.Buffer
	if _, err := store.BackupCase(ctx, &backup); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(backup.Bytes(), []byte("search_page_indexed")) {
		t.Fatal("el respaldo conserva una marca derivada")
	}
	if _, err := destination.RestoreCase(ctx, &backup); err != nil {
		t.Fatal(err)
	}
	restored, err := destination.Page(ctx, PageRequest{Search: "Título vigente"})
	if err != nil || !reflect.DeepEqual(restored, current) {
		t.Fatalf("búsqueda restaurada: %+v, %v", restored, err)
	}
	original, err := destination.RecordRevision(ctx, note, 1)
	if err != nil || original.Title != "Título anterior" {
		t.Fatalf("cita original: %+v, %v", original, err)
	}
}

func TestPostgresSearchCompletesLargeBatchInParts(t *testing.T) {
	store := openAuditTest(t)
	ctx := t.Context()
	batch := make([]Record, 1001)
	for index := range batch {
		batch[index] = Record{Kind: "dns", Title: "Muestra de volumen", Time: Now()}
	}
	batch[0] = Record{Kind: "nota", Title: "Nota anterior", Time: Now(), Details: "Versión inicial"}
	batch[len(batch)-1].Title = "Último dato buscado"
	if err := store.Save(batch); err != nil {
		t.Fatal(err)
	}
	page, err := store.Page(ctx, PageRequest{Search: "Último dato buscado"})
	if err != nil || len(page.Rows) != 1 {
		t.Fatalf("búsqueda durante la preparación: %+v, %v", page, err)
	}
	key, ordinal, valid := recordPosition(page.Rows[0].ID)
	if !valid || ordinal != len(batch) {
		t.Fatalf("id: %q", page.Rows[0].ID)
	}
	var position int
	var indexed bool
	if err := store.db.QueryRowContext(ctx, `
		SELECT search_page_position, search_page_indexed FROM pavarotti_evidence_batches
		WHERE expediente = $1 AND batch_key = $2`, store.expediente, key).Scan(&position, &indexed); err != nil || indexed || position != 1001 {
		t.Fatalf("primera parte: %d, %t, %v", position, indexed, err)
	}
	if _, err := store.Edit(key+"-1", 1, "Nota vigente", "", "Segunda revisión"); err != nil {
		t.Fatal(err)
	}
	current, err := store.Page(ctx, PageRequest{Search: "Nota vigente"})
	if err != nil || len(current.Rows) != 1 || current.Rows[0].ID != key+"-1" {
		t.Fatalf("nota actualizada durante la preparación: %+v, %v", current, err)
	}
	var projected int
	if err := store.db.QueryRowContext(ctx, "SELECT count(*) FROM pavarotti_search_page WHERE expediente = $1",
		store.expediente).Scan(&projected); err != nil || projected != len(batch) {
		t.Fatalf("proyección final: %d, %v", projected, err)
	}
}
