package caso

import (
	"bytes"
	"reflect"
	"testing"
)

func TestPostgresHTTPIndexRebuildsCaseAndRestoresCitations(t *testing.T) {
	store, other := openAuditTest(t), openAuditTest(t)
	ctx := t.Context()
	if _, err := store.db.ExecContext(ctx, `
		INSERT INTO pavarotti_evidence_batches (expediente, batch_key, payload)
		SELECT $1, lpad(to_hex(series.n), 64, '0'), jsonb_build_array(
			jsonb_build_object('kind', 'nota', 'time', '2026-11-18T20:00:00Z', 'title', 'Nota combinada'),
			jsonb_build_object('kind', 'archivo HAR', 'time', '2026-11-19T00:00:00.123456789Z', 'title', 'GET 204',
				'source', 'https://192.0.2.1', 'traffic', jsonb_build_object('method', 'GET', 'status', 204),
				'signals', jsonb_build_array('Sin cabecera'), 'http_findings', jsonb_build_array(jsonb_build_object('rule', 'hsts-ausente')))
		)
		FROM generate_series(1, $2::integer) AS series(n)
	`, store.expediente, maxHTTPBackfillBatches+1); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		"DELETE FROM pavarotti_http_page WHERE expediente = $1",
		"UPDATE pavarotti_evidence_batches SET http_page_indexed = false WHERE expediente = $1",
	} {
		if _, err := store.db.ExecContext(ctx, statement, store.expediente); err != nil {
			t.Fatal(err)
		}
	}
	query := PageRequest{Kind: "http", Limit: 2, HTTPFrom: "2026-11-19", HTTPTo: "2026-11-19",
		HTTPClass: 2, HTTPSource: "archivo HAR", HTTPMethod: "GET", HTTPRule: "hsts-ausente"}
	fallback, err := store.Page(ctx, query)
	if err != nil || fallback.Next == "" || len(fallback.Rows) != 2 {
		t.Fatalf("página durante la actualización: %+v, %v", fallback, err)
	}
	var pending int
	if err := store.db.QueryRowContext(ctx, "SELECT count(*) FROM pavarotti_evidence_batches WHERE expediente = $1 AND NOT http_page_indexed",
		store.expediente).Scan(&pending); err != nil || pending != 1 {
		t.Fatalf("lotes pendientes: %d, %v", pending, err)
	}
	indexed, err := store.Page(ctx, query)
	if err != nil || !reflect.DeepEqual(indexed, fallback) {
		t.Fatalf("página indexada: %+v, %v", indexed, err)
	}
	query.After = indexed.Next
	second, err := store.Page(ctx, query)
	if err != nil || len(second.Rows) != 2 || second.Rows[0].ID == indexed.Rows[1].ID || second.Next == indexed.Next {
		t.Fatalf("segunda página: %+v, %v", second, err)
	}
	id := indexed.Rows[0].ID
	record, err := store.RecordRevision(ctx, id, 1)
	key, ordinal, valid := recordPosition(id)
	if err != nil || !valid || ordinal != 2 || record.ID != id || record.Time != indexed.Rows[0].Time ||
		record.Traffic == nil || record.Traffic.Status != 204 {
		t.Fatalf("cita: %+v, %v", record, err)
	}
	if _, err := store.db.ExecContext(ctx, "UPDATE pavarotti_evidence_batches SET http_page_indexed = false WHERE expediente = $1 AND batch_key = $2",
		store.expediente, key); err != nil {
		t.Fatal(err)
	}
	query.After = ""
	failedPreparation, err := store.Page(ctx, query)
	if err != nil || !reflect.DeepEqual(failedPreparation, fallback) {
		t.Fatalf("lectura tras fallar la preparación: %+v, %v", failedPreparation, err)
	}

	var backup bytes.Buffer
	if _, err := store.BackupCase(ctx, &backup); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(backup.Bytes(), []byte("http_page_indexed")) {
		t.Fatal("la copia incluye el índice derivado")
	}
	if _, err := other.RestoreCase(ctx, &backup); err != nil {
		t.Fatal(err)
	}
	if err := other.Save([]Record{{Kind: "hallazgo", Title: "Incorporación posterior", Time: Now()}}); err != nil {
		t.Fatal(err)
	}
	var ready int
	if err := other.db.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE http_page_indexed AND search_page_indexed),
		count(*) FILTER (WHERE NOT http_page_indexed AND NOT search_page_indexed)
		FROM pavarotti_evidence_batches WHERE expediente = $1`, other.expediente).Scan(&ready, &pending); err != nil ||
		ready != 1 || pending != maxHTTPBackfillBatches+1 {
		t.Fatalf("proyecciones diferidas y escritura posterior: %d listas, %d pendientes, %v", ready, pending, err)
	}
	restored, err := other.Page(ctx, query)
	if err != nil || !reflect.DeepEqual(restored, fallback) {
		t.Fatalf("página restaurada: %+v, %v", restored, err)
	}
	restored, err = other.Page(ctx, query)
	if err != nil || !reflect.DeepEqual(restored, fallback) {
		t.Fatalf("página reindexada: %+v, %v", restored, err)
	}
	if err := other.db.QueryRowContext(ctx, "SELECT count(*) FROM pavarotti_evidence_batches WHERE expediente = $1 AND NOT http_page_indexed",
		other.expediente).Scan(&pending); err != nil || pending != 0 {
		t.Fatalf("índice de la restauración: %d lotes pendientes, %v", pending, err)
	}
}

func TestIndexedHTTPPageReadsEditedNoteMetadata(t *testing.T) {
	store := openAuditTest(t)
	if err := store.Save([]Record{{
		Kind: "nota", Time: "2026-11-19T00:00:00Z", Title: "Anterior", Source: "https://192.0.2.1",
		Traffic: &Traffic{Status: 204}, Details: "Versión anterior",
	}}); err != nil {
		t.Fatal(err)
	}
	original, err := store.Page(t.Context(), PageRequest{Kind: "http"})
	if err != nil || len(original.Rows) != 1 {
		t.Fatalf("nota original: %+v, %v", original, err)
	}
	if _, err := store.Edit(original.Rows[0].ID, 1, "Revisada", "", "Versión vigente"); err != nil {
		t.Fatal(err)
	}
	current, err := store.Page(t.Context(), PageRequest{Kind: "http"})
	if err != nil || len(current.Rows) != 1 || current.Rows[0].Title != "Revisada" || current.Rows[0].Source != "" {
		t.Fatalf("nota vigente: %+v, %v", current, err)
	}
	found, err := store.Page(t.Context(), PageRequest{Kind: "http", Search: "Revisada"})
	if err != nil || !reflect.DeepEqual(current, found) {
		t.Fatalf("búsqueda de nota: %+v, %v", found, err)
	}
}
