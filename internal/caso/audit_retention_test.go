package caso

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"
)

func TestAuditRetentionRequiresRecoverableEvents(t *testing.T) {
	source, other, recovered := openAuditTest(t), openAuditTest(t), openAuditTest(t)
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Second)
	firstCutoff := now.Add(-60 * time.Hour)
	lastCutoff := now.Add(-24 * time.Hour)
	noteID := backupTestNote(t, source, "Nota con historial")
	if _, err := source.db.ExecContext(ctx, `UPDATE pavarotti_audit_events SET occurred_at = $2 WHERE expediente = $1`,
		source.expediente, now.Add(-72*time.Hour)); err != nil {
		t.Fatal(err)
	}
	var old bytes.Buffer
	if _, err := source.BackupCase(ctx, &old); err != nil {
		t.Fatal(err)
	}
	if _, err := source.EditContext(ctx, noteID, 1, "Segunda revisión", "", "Evidencia conservada"); err != nil {
		t.Fatal(err)
	}
	backupTestNote(t, source, "En el límite")
	if _, err := source.db.ExecContext(ctx, `UPDATE pavarotti_audit_events
		SET occurred_at = CASE WHEN position = 2 THEN $2::timestamptz ELSE $3::timestamptz END WHERE expediente = $1 AND position IN (2,3)`,
		source.expediente, now.Add(-48*time.Hour), lastCutoff); err != nil {
		t.Fatal(err)
	}
	backupTestNote(t, other, "Expediente independiente")
	if _, err := other.db.ExecContext(ctx, `UPDATE pavarotti_audit_events SET occurred_at = $2 WHERE expediente = $1`,
		other.expediente, now.Add(-72*time.Hour)); err != nil {
		t.Fatal(err)
	}
	preview, err := source.PreviewAuditRetention(ctx, lastCutoff)
	if err != nil || preview.Candidates != 2 || preview.Removed != 0 {
		t.Fatalf("vista previa: %+v, %v", preview, err)
	}
	if _, err := source.ApplyAuditRetention(ctx, lastCutoff, bytes.NewReader(old.Bytes())); !errors.Is(err, ErrRetentionCoverage) {
		t.Fatalf("respaldo sin una revisión: %v", err)
	}
	var archive bytes.Buffer
	backup, err := source.BackupCase(ctx, &archive)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.ApplyAuditRetention(ctx, lastCutoff, bytes.NewReader(archive.Bytes())); !errors.Is(err, ErrRetentionCoverage) {
		t.Fatalf("respaldo de otro expediente: %v", err)
	}
	if _, err := source.ApplyAuditRetention(ctx, lastCutoff, bytes.NewReader(archive.Bytes()[:archive.Len()-1])); !errors.Is(err, ErrBackupIntegrity) {
		t.Fatalf("respaldo truncado: %v", err)
	}
	preview, err = source.PreviewAuditRetention(ctx, lastCutoff)
	if err != nil || preview.Candidates != 2 {
		t.Fatalf("actividad tras respaldos rechazados: %+v, %v", preview, err)
	}
	for _, cutoff := range []time.Time{firstCutoff, lastCutoff} {
		applied, err := source.ApplyAuditRetention(ctx, cutoff, bytes.NewReader(archive.Bytes()))
		if err != nil || applied.Candidates != 1 || applied.Removed != 1 || applied.BackupSHA256 != backup.SHA256 {
			t.Fatalf("retención en %s: %+v, %v", cutoff, applied, err)
		}
	}
	current, err := source.AuditPage(ctx, 0, 50)
	if err != nil || len(current.Events) != 3 || current.Events[2].Position != 3 || current.Events[0].Position != 5 ||
		current.Events[0].Action != AuditRetention || current.Events[0].Details.RemovedEvents != 1 ||
		current.Events[0].Details.RetentionBefore != lastCutoff.Format(time.RFC3339Nano) || current.Events[0].Details.BackupSHA256 != backup.SHA256 {
		t.Fatalf("actividad después de retención: %+v, %v", current, err)
	}
	if original, err := source.RecordRevision(ctx, noteID, 1); err != nil || original.Title != "Nota con historial" {
		t.Fatalf("revisión histórica: %+v, %v", original, err)
	}
	if revised, err := source.RecordRevision(ctx, noteID, 2); err != nil || revised.Details != "Evidencia conservada" {
		t.Fatalf("revisión vigente: %+v, %v", revised, err)
	}
	if _, err := recovered.RestoreCase(ctx, bytes.NewReader(archive.Bytes())); err != nil {
		t.Fatal(err)
	}
	page, err := recovered.AuditPage(ctx, 0, 50)
	if err != nil || len(page.Events) != 4 || page.Events[2].Action != AuditEdit || page.Events[3].Action != AuditNote {
		t.Fatalf("actividad recuperada desde el respaldo: %+v, %v", page, err)
	}
}

func TestAuditRetentionRechecksConcurrentSelection(t *testing.T) {
	store := openAuditTest(t)
	ctx := t.Context()
	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	backupTestNote(t, store, "Actividad antigua")
	if _, err := store.db.ExecContext(ctx, `UPDATE pavarotti_audit_events SET occurred_at = $2 WHERE expediente = $1`,
		store.expediente, cutoff.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	if _, err := store.BackupCase(ctx, &archive); err != nil {
		t.Fatal(err)
	}
	header := bytes.IndexByte(archive.Bytes(), '\n') + 1
	gate := &backupTestReader{Reader: bytes.NewReader(archive.Bytes()[header:]), started: make(chan struct{})}
	start := gate.started
	resume := make(chan struct{})
	gate.resume = resume
	defer close(resume)
	ending := make(chan error, 1)
	go func() {
		_, err := store.ApplyAuditRetention(ctx, cutoff, io.MultiReader(bytes.NewReader(archive.Bytes()[:header]), gate))
		ending <- err
	}()
	select {
	case <-start:
	case err := <-ending:
		t.Fatalf("la comprobación terminó antes de comparar la copia: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("la comprobación no llegó a leer los eventos respaldados")
	}
	if applied, err := store.ApplyAuditRetention(ctx, cutoff, bytes.NewReader(archive.Bytes())); err != nil || applied.Removed != 1 {
		t.Fatalf("primera aplicación completa: %+v, %v", applied, err)
	}
	resume <- struct{}{}
	if err := <-ending; !errors.Is(err, ErrRetentionChanged) {
		t.Fatalf("selección concurrente: %v", err)
	}
	audit, err := store.AuditPage(ctx, 0, 50)
	if err != nil || len(audit.Events) != 1 || audit.Events[0].Action != AuditRetention {
		t.Fatalf("actividad después de aplicar dos veces: %+v, %v", audit, err)
	}
}
