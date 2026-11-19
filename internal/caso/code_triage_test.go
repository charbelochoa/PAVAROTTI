package caso

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"testing"
)

var fixtureSignal = FindingKey{Rule: "http-cliente-timeout", Line: 3, Column: 9}

func fixtureCode(t *testing.T, store *Store) Record {
	t.Helper()
	entry := Record{Kind: "código", Time: "2026-01-01T00:00:00Z", Title: "Prueba", SHA256: Hash([]byte("source")),
		Review: &CodeReview{Package: "fixture", Signals: []Finding{{Line: fixtureSignal.Line, Column: fixtureSignal.Column, Rule: fixtureSignal.Rule}}}}
	if err := store.Save([]Record{entry}); err != nil {
		t.Fatal(err)
	}
	rows, err := store.Records()
	if err != nil || len(rows) != 1 {
		t.Fatalf("registro de prueba: %+v, %v", rows, err)
	}
	return rows[0]
}

func TestCodeTriageLocal(t *testing.T) {
	path := t.TempDir()
	first, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	testCodeTriage(t, first, second, fixtureCode(t, first))
}

func TestCodeTriagePostgresAndMigration(t *testing.T) {
	dsn := os.Getenv("PAVAROTTI_TEST_POSTGRES")
	if dsn == "" {
		t.Skip("PAVAROTTI_TEST_POSTGRES no configurado")
	}
	ctx := t.Context()
	name := "test-triage-" + hex.EncodeToString(randBytes(t))
	first, err := OpenPostgres(ctx, dsn, name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		defer first.Close()
		if _, err := first.db.ExecContext(context.Background(), "DELETE FROM pavarotti_evidence_batches WHERE expediente = $1", name); err != nil {
			t.Error(err)
		}
	})
	second, err := OpenPostgres(ctx, dsn, name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	path := t.TempDir()
	local, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	entry := fixtureCode(t, local)
	if count, err := first.ImportLocal(path); err != nil || count != 1 {
		t.Fatalf("importación inicial: %d, %v", count, err)
	}
	if _, err := local.ClassifyCode(ctx, entry.ID, fixtureSignal, 0, "confirmada", "Criterio original"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if count, err := first.ImportLocal(path); err != nil || count != 0 {
			t.Fatalf("migración idempotente: %d, %v", count, err)
		}
	}
	history, err := first.CodeHistory(ctx, entry.ID, fixtureSignal)
	if err != nil || len(history) != 1 || history[0].Reason != "Criterio original" {
		t.Fatalf("historial migrado: %+v, %v", history, err)
	}
	if _, err := second.ClassifyCode(ctx, entry.ID, fixtureSignal, 1, "descartada", "Corrección de criterio"); err != nil {
		t.Fatal(err)
	}
	if _, err := local.ClassifyCode(ctx, entry.ID, fixtureSignal, 1, "pendiente", "Otra decisión"); err != nil {
		t.Fatal(err)
	}
	if _, err := first.ImportLocal(path); !errors.Is(err, ErrMigrationConflict) {
		t.Fatalf("conflicto de historial: %v", err)
	}
	history, err = first.CodeHistory(ctx, entry.ID, fixtureSignal)
	if err != nil || len(history) != 2 || history[1].Status != "descartada" {
		t.Fatalf("historial tras conflicto: %+v, %v", history, err)
	}
	testCodeTriage(t, first, second, entry)
}

func testCodeTriage(t *testing.T, first, second *Store, original Record) {
	t.Helper()
	ctx := t.Context()
	id := original.ID
	if _, err := first.ClassifyCode(ctx, id, fixtureSignal, 0, "confirmada", " "); !errors.Is(err, ErrInvalidTriage) {
		t.Fatalf("justificación vacía: %v", err)
	}
	unknown := FindingKey{Rule: fixtureSignal.Rule, Line: 77, Column: 1}
	if _, err := first.ClassifyCode(ctx, id, unknown, 0, "confirmada", "No existe"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("señal inexistente: %v", err)
	}
	initial, err := first.CodeHistory(ctx, id, fixtureSignal)
	if err != nil {
		t.Fatal(err)
	}
	outcomes := make(chan error, 2)
	for _, handle := range []*Store{first, second} {
		go func() {
			_, err := handle.ClassifyCode(ctx, id, fixtureSignal, len(initial), "confirmada", "Validada manualmente")
			outcomes <- err
		}()
	}
	var success, conflicts int
	for range 2 {
		err := <-outcomes
		switch {
		case err == nil:
			success++
		case errors.Is(err, ErrRevisionConflict):
			conflicts++
		default:
			t.Fatal(err)
		}
	}
	if success != 1 || conflicts != 1 {
		t.Fatalf("escritura concurrente: %d éxitos y %d conflictos", success, conflicts)
	}
	history, err := second.CodeHistory(ctx, id, fixtureSignal)
	if err != nil || len(history) != len(initial)+1 || history[len(history)-1].Time == "" {
		t.Fatalf("historial persistido: %+v, %v", history, err)
	}
	current, err := second.CodeClassifications(ctx, id)
	if err != nil || len(current) != 1 || current[0] != history[len(history)-1] {
		t.Fatalf("clasificación vigente: %+v, %v", current, err)
	}
	still, err := second.RecordRevision(ctx, id, original.Revision)
	if err != nil || still.SHA256 != original.SHA256 || !still.hasSignal(fixtureSignal) {
		t.Fatalf("evidencia citada: %+v, %v", still, err)
	}
}
