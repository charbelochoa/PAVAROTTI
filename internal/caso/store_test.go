package caso

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLegacyLocalIDs(t *testing.T) {
	path := t.TempDir()
	old := []byte(`[{"kind":"nota","time":"2026-01-01T00:00:00Z","title":"Anterior","details":"Evidencia manual"}]`)
	key := Hash(old)
	if err := os.WriteFile(filepath.Join(path, key+".json"), old, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	records, err := store.Records()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].ID != key+"-1" || records[0].Revision != 1 {
		t.Fatalf("registros legados: %+v", records)
	}
	if err := store.Save(records); err != nil {
		t.Fatal(err)
	}
	records, err = store.Records()
	if err != nil || len(records) != 1 {
		t.Fatalf("deduplicación legada: %+v, %v", records, err)
	}
}

func TestNotesAndEvidenceLocal(t *testing.T) {
	path := t.TempDir()
	first, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	checkStore(t, first, second)
}

func TestNotesAndEvidencePostgres(t *testing.T) {
	dsn := os.Getenv("PAVAROTTI_TEST_POSTGRES")
	if dsn == "" {
		t.Skip("PAVAROTTI_TEST_POSTGRES no configurado")
	}
	expediente := "test-" + hex.EncodeToString(randBytes(t))
	first, err := OpenPostgres(t.Context(), dsn, expediente)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		defer first.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := first.db.ExecContext(ctx, `DELETE FROM pavarotti_note_revisions WHERE expediente = $1`, expediente); err != nil {
			t.Error(err)
		}
		if _, err := first.db.ExecContext(ctx, `DELETE FROM pavarotti_evidence_batches WHERE expediente = $1`, expediente); err != nil {
			t.Error(err)
		}
	})
	second, err := OpenPostgres(t.Context(), dsn, expediente)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	checkStore(t, first, second)
	other, err := OpenPostgres(t.Context(), dsn, expediente+"-otro")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	records, err := other.Records()
	if err != nil || len(records) != 0 {
		t.Fatalf("aislamiento de expedientes: %+v, %v", records, err)
	}
	checkMigration(t, first)
}

func checkMigration(t *testing.T, destination *Store) {
	t.Helper()
	path := t.TempDir()
	source, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Save([]Record{{Kind: "nota", Time: Now(), Title: "Migrar", Details: "Original local"}}); err != nil {
		t.Fatal(err)
	}
	records, err := source.Records()
	if err != nil || len(records) != 1 {
		t.Fatalf("expediente de origen: %+v, %v", records, err)
	}
	id := records[0].ID
	if _, err := source.Edit(id, 1, "Migrada", "", "Revisión local"); err != nil {
		t.Fatal(err)
	}
	if count, err := destination.ImportLocal(path); err != nil || count != 1 {
		t.Fatalf("primera importación: %d, %v", count, err)
	}
	if count, err := destination.ImportLocal(path); err != nil || count != 0 {
		t.Fatalf("reimportación: %d, %v", count, err)
	}
	history, err := destination.History(id)
	if err != nil || len(history) != 1 || history[0].Details != "Original local" {
		t.Fatalf("historial migrado: %+v, %v", history, err)
	}
	if _, err := destination.Edit(id, 2, "Destino", "", "Revisión de destino"); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Edit(id, 2, "Origen", "", "Revisión local en conflicto"); err != nil {
		t.Fatal(err)
	}
	if err := source.Save([]Record{{Kind: "nota", Time: Now(), Title: "Sujeta al rollback", Details: "No debe copiarse"}}); err != nil {
		t.Fatal(err)
	}
	before, err := destination.Records()
	if err != nil {
		t.Fatal(err)
	}
	if count, err := destination.ImportLocal(path); count != 0 || !errors.Is(err, ErrMigrationConflict) {
		t.Fatalf("conflicto de migración: %d, %v", count, err)
	}
	after, err := destination.Records()
	if err != nil || len(after) != len(before) {
		t.Fatalf("estado tras conflicto: %+v, %v", after, err)
	}
}

func randBytes(t *testing.T) []byte {
	t.Helper()
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	return buf
}

func checkStore(t *testing.T, first, second *Store) {
	t.Helper()
	originalTime := "2026-01-01T00:00:00Z"
	origNote := Record{Kind: "nota", Time: originalTime, Title: "Nota", Details: "Dato original"}
	imported := Record{Kind: "hallazgo", Time: originalTime, Title: "Hallazgo", Source: "Fuente de prueba",
		SourceID: "37", SHA256: Hash([]byte("fuente original"))}
	if err := first.Save([]Record{origNote}); err != nil {
		t.Fatal(err)
	}
	type importOutcome struct {
		result SaveResult
		err    error
	}
	imports := make(chan importOutcome, 2)
	for _, handle := range []*Store{first, second} {
		go func() {
			result, err := handle.SaveEvidence(t.Context(), []Record{imported})
			imports <- importOutcome{result, err}
		}()
	}
	var totals SaveResult
	for range 2 {
		outcome := <-imports
		if outcome.err != nil {
			t.Fatal(outcome.err)
		}
		totals.Imported += outcome.result.Imported
		totals.Duplicates += outcome.result.Duplicates
	}
	if totals != (SaveResult{Imported: 1, Duplicates: 1}) {
		t.Fatalf("recuento de importación: %+v", totals)
	}
	records, err := second.Records()
	if err != nil || len(records) != 2 {
		t.Fatalf("deduplicación: %+v, %v", records, err)
	}
	var note Record
	for _, record := range records {
		if record.Kind == "hallazgo" {
			if _, err := first.Edit(record.ID, 1, "Cambio", "", "Detalle"); !errors.Is(err, ErrReadOnly) {
				t.Fatalf("evidencia modificable: %v", err)
			}
			if record.SourceID != imported.SourceID || record.SHA256 != imported.SHA256 {
				t.Fatalf("procedencia: %+v", record)
			}
		} else {
			note = record
		}
	}
	if note.ID == "" || note.Revision != 1 {
		t.Fatalf("nota inicial: %+v", note)
	}
	outcomes := make(chan error, 2)
	for _, handle := range []*Store{first, second} {
		go func(store *Store) {
			_, err := store.Edit(note.ID, 1, "Edición paralela", "Origen", "Texto nuevo")
			outcomes <- err
		}(handle)
	}
	var successes, conflicts int
	for range 2 {
		switch err := <-outcomes; {
		case err == nil:
			successes++
		case errors.Is(err, ErrRevisionConflict):
			conflicts++
		default:
			t.Fatal(err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("ediciones concurrentes: %d aceptadas y %d conflictos", successes, conflicts)
	}
	last, err := first.Edit(note.ID, 2, "Última versión", "Origen", "Texto final")
	if err != nil || last.Revision != 3 || last.UpdatedAt == "" || last.Time != originalTime {
		t.Fatalf("última revisión: %+v, %v", last, err)
	}
	history, err := second.History(note.ID)
	if err != nil || len(history) != 2 || history[0].Details != origNote.Details || history[1].Details != "Texto nuevo" {
		t.Fatalf("historial: %+v, %v", history, err)
	}
	records, err = second.Records()
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		if record.ID == note.ID {
			if record.Revision != 3 || record.Title != "Última versión" {
				t.Fatalf("lectura de revisión: %+v", record)
			}
			return
		}
	}
	data, _ := json.Marshal(records)
	t.Fatalf("nota ausente: %s", data)
}
