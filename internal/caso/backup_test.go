package caso

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestCaseBackupRestoresHistoryAndJobs(t *testing.T) {
	source := openAuditTest(t)
	destinationDSN := os.Getenv("PAVAROTTI_TEST_POSTGRES_RESTORE")
	if destinationDSN == "" {
		destinationDSN = os.Getenv("PAVAROTTI_TEST_POSTGRES")
	}
	destination := openAuditTestAt(t, destinationDSN)
	ctx := t.Context()
	code := fixtureCode(t, source)
	if _, err := source.ClassifyCode(ctx, code.ID, fixtureSignal, 0, "confirmada", "Se revisó la evidencia"); err != nil {
		t.Fatal(err)
	}
	noteID := backupTestNote(t, source, "Nota anterior")
	if _, err := source.EditContext(ctx, noteID, 1, "Nota vigente", "", "Versión 2"); err != nil {
		t.Fatal(err)
	}
	const password = "contraseña exclusiva de la prueba"
	account, err := source.SaveSharedAccount(ctx, "cuenta-prueba-respaldo", SharedReader, password)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := source.RevokeSharedAccount(context.Background(), account.Name); err != nil {
			t.Error(err)
		}
	})
	session, _, err := source.OpenSharedSession(ctx, account.Name, password)
	if err != nil {
		t.Fatal(err)
	}
	claim := func(label string) AnalysisClaim {
		t.Helper()
		job, err := source.EnqueueAnalysis(ctx, Hash([]byte(label)), "respaldo", 1,
			json.RawMessage(`{"records":[{"id":"`+noteID+`","revision":1}]}`))
		if err != nil {
			t.Fatal(err)
		}
		assigned, found, err := source.ClaimAnalysis(ctx, "respaldo")
		if err != nil || !found || assigned.Job.ID != job.ID {
			t.Fatalf("asignación: %+v, %v", assigned, err)
		}
		return assigned
	}
	finished := claim("completa")
	if err := source.FinishAnalysis(ctx, finished, json.RawMessage(`{"reference":"`+noteID+`"}`), ""); err != nil {
		t.Fatal(err)
	}
	running, exhausted := claim("pendiente"), claim("agotada")
	if _, err := source.db.ExecContext(ctx, `UPDATE pavarotti_analysis_jobs SET attempts = $3
		WHERE expediente = $1 AND id = $2`, source.expediente, exhausted.Job.ID, AnalysisMaxAttempts); err != nil {
		t.Fatal(err)
	}
	originalAudit, err := source.AuditPage(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var file bytes.Buffer
	exported, err := source.BackupCase(ctx, &file)
	if err != nil || exported.SourceCase != source.expediente || exported.Rows["batch"] != 2 || exported.Rows["note_revision"] != 1 ||
		exported.Rows["triage_revision"] != 1 || exported.Rows["job"] != 3 || exported.Rows["audit_event"] != len(originalAudit.Events) {
		t.Fatalf("manifiesto: %+v, %v", exported, err)
	}
	for _, private := range []string{password, account.Name, session, running.Token, exhausted.Token, "password_hash", "lease_token"} {
		if bytes.Contains(file.Bytes(), []byte(private)) {
			t.Fatal("el respaldo contiene material de autenticación")
		}
	}
	checked, err := InspectCaseBackup(ctx, bytes.NewReader(file.Bytes()))
	if err != nil || !reflect.DeepEqual(checked, exported) {
		t.Fatalf("verificación: %+v, %v", checked, err)
	}
	restored, err := destination.RestoreCase(ctx, bytes.NewReader(file.Bytes()))
	if err != nil || !reflect.DeepEqual(restored, exported) {
		t.Fatalf("restauración: %+v, %v", restored, err)
	}
	for _, revision := range []int{1, 2} {
		want, err := source.RecordRevision(ctx, noteID, revision)
		if err != nil {
			t.Fatal(err)
		}
		got, err := destination.RecordRevision(ctx, noteID, revision)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("nota restaurada %d: %+v, %v", revision, got, err)
		}
	}
	decisions, err := destination.CodeHistory(ctx, code.ID, fixtureSignal)
	if err != nil || len(decisions) != 1 || decisions[0].Status != "confirmada" {
		t.Fatalf("triaje restaurado: %+v, %v", decisions, err)
	}
	for id, status := range map[string]string{finished.Job.ID: "succeeded", running.Job.ID: "queued", exhausted.Job.ID: "failed"} {
		job, err := destination.AnalysisJob(ctx, id)
		if err != nil || job.State != status || (status == "succeeded" && !bytes.Contains(job.Result, []byte(noteID))) {
			t.Fatalf("tarea restaurada: %+v, %v", job, err)
		}
	}
	continued, found, err := destination.ClaimAnalysis(ctx, "respaldo")
	if err != nil || !found || continued.Job.ID != running.Job.ID || continued.Job.Attempts != 2 ||
		continued.Token == running.Token || !bytes.Contains(continued.Snapshot, []byte(noteID)) {
		t.Fatalf("tarea recuperada: %+v, %v", continued.Job, err)
	}
	sourceJob, err := source.AnalysisJob(ctx, running.Job.ID)
	if err != nil || sourceJob.State != "running" {
		t.Fatalf("tarea de origen modificada: %+v, %v", sourceJob, err)
	}
	page, err := destination.AuditPage(ctx, 0, 100)
	if err != nil || len(page.Events) != len(originalAudit.Events)+2 || page.Events[1].Action != AuditRestore ||
		page.Events[1].Details.BackupSHA256 != exported.SHA256 || !reflect.DeepEqual(page.Events[2:], originalAudit.Events) {
		t.Fatalf("actividad restaurada: %+v, %v", page, err)
	}
	if _, _, err := destination.OpenSharedSession(ctx, account.Name, password); !errors.Is(err, ErrSharedCredentials) {
		t.Fatalf("la cuenta se trasladó junto con la copia: %v", err)
	}
	if _, err := destination.RestoreCase(ctx, bytes.NewReader(file.Bytes())); !errors.Is(err, ErrBackupDestination) {
		t.Fatalf("segundo intento sobre un destino ocupado: %v", err)
	}
}

func TestCaseBackupSnapshotAndRollback(t *testing.T) {
	source, destination := openAuditTest(t), openAuditTest(t)
	ctx := t.Context()
	noteID := backupTestNote(t, source, "Nota anterior")
	if err := source.Save([]Record{{Kind: "hallazgo", Time: Now(), Title: "Evidencia extensa", Details: string(bytes.Repeat([]byte("x"), 80<<10))}}); err != nil {
		t.Fatal(err)
	}
	var file bytes.Buffer
	writer := &backupTestWriter{Writer: &file, firstWrite: func() error {
		_, err := source.EditContext(ctx, noteID, 1, "Cambió durante la copia", "", "Desde otra transacción")
		return err
	}}
	exported, err := source.BackupCase(ctx, writer)
	if err != nil || exported.Rows["note_revision"] != 0 {
		t.Fatalf("instantánea consistente: %+v, %v", exported, err)
	}
	if _, err := source.RecordRevision(ctx, noteID, 2); err != nil {
		t.Fatalf("edición concurrente: %v", err)
	}
	for _, invalid := range [][]byte{
		file.Bytes()[:file.Len()-1],
		bytes.Replace(file.Bytes(), []byte(`"source_case":"`), []byte(`"source_case":"x`), 1),
		append(bytes.Clone(file.Bytes()), '\n'),
	} {
		if _, err := destination.RestoreCase(ctx, bytes.NewReader(invalid)); !errors.Is(err, ErrBackupIntegrity) {
			t.Fatalf("respaldo inválido: %v", err)
		}
		if items, err := destination.Records(); err != nil || len(items) != 0 {
			t.Fatalf("cambios parciales: %d, %v", len(items), err)
		}
	}
	if _, err := destination.RestoreCase(ctx, bytes.NewReader(file.Bytes())); err != nil {
		t.Fatal(err)
	}
	if _, err := destination.RecordRevision(ctx, noteID, 2); !errors.Is(err, ErrNotFound) {
		t.Fatalf("el respaldo incluyó una revisión posterior a la instantánea: %v", err)
	}
}

func TestCaseRestoreSerializesDestinationWrites(t *testing.T) {
	source, destination := openAuditTest(t), openAuditTest(t)
	ctx := t.Context()
	backupTestNote(t, source, "Nota a restaurar")
	var file bytes.Buffer
	if _, err := source.BackupCase(ctx, &file); err != nil {
		t.Fatal(err)
	}
	headerEnd := bytes.IndexByte(file.Bytes(), '\n') + 1
	started := make(chan struct{})
	resume := make(chan struct{})
	gate := &backupTestReader{Reader: bytes.NewReader(file.Bytes()[headerEnd:]), started: started, resume: resume}
	input := io.MultiReader(bytes.NewReader(file.Bytes()[:headerEnd]), gate)
	restored := make(chan error, 1)
	go func() {
		_, err := destination.RestoreCase(ctx, input)
		restored <- err
	}()
	defer close(resume)
	select {
	case <-started:
	case err := <-restored:
		t.Fatalf("la restauración terminó antes de leer el cuerpo: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("la restauración no llegó al cuerpo")
	}
	short, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer cancel()
	if _, err := destination.SaveEvidence(short, []Record{{Kind: "nota", Title: "Competidor"}}); err == nil {
		t.Fatal("otra escritura entró antes de que terminara la restauración")
	}
	resume <- struct{}{}
	if err := <-restored; err != nil {
		t.Fatal(err)
	}
	if items, err := destination.Records(); err != nil || len(items) != 1 || items[0].Title != "Nota a restaurar" {
		t.Fatalf("estado tras restaurar: %+v, %v", items, err)
	}
}

func TestCaseRestoreRejectsInvalidEvidenceReferences(t *testing.T) {
	source, destination := openAuditTest(t), openAuditTest(t)
	ctx := t.Context()
	noteID := backupTestNote(t, source, "Nota citada")
	if _, err := source.EditContext(ctx, noteID, 1, "Nueva revisión", "", "Edición de prueba"); err != nil {
		t.Fatal(err)
	}
	var file, broken bytes.Buffer
	summary, err := source.BackupCase(ctx, &file)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range bytes.SplitAfter(bytes.TrimSuffix(file.Bytes(), []byte("\n")), []byte("\n")) {
		var frame backupFrame
		if err := json.Unmarshal(line, &frame); err != nil {
			t.Fatal(err)
		}
		switch frame.Type {
		case "end":
			if err := encodeBackupFrame(&broken, "end", backupFooter{SHA256: Hash(broken.Bytes()), Rows: summary.Rows}); err != nil {
				t.Fatal(err)
			}
		case "note_revision":
			var revision map[string]json.RawMessage
			if err := json.Unmarshal(frame.Data, &revision); err != nil {
				t.Fatal(err)
			}
			revision["ordinal"] = json.RawMessage(`2`)
			if err := encodeBackupFrame(&broken, frame.Type, revision); err != nil {
				t.Fatal(err)
			}
		default:
			broken.Write(line)
		}
	}
	if _, err := InspectCaseBackup(ctx, bytes.NewReader(broken.Bytes())); err != nil {
		t.Fatalf("el archivo de prueba debe conservar su checksum y estructura: %v", err)
	}
	if _, err := destination.RestoreCase(ctx, bytes.NewReader(broken.Bytes())); !errors.Is(err, ErrBackupIntegrity) {
		t.Fatalf("el ordinal inexistente no fue rechazado: %v", err)
	}
	if records, err := destination.Records(); err != nil || len(records) != 0 {
		t.Fatalf("copia aplicada parcialmente: %+v, %v", records, err)
	}
}

func TestCaseRestoreRollsBackMultipleBatches(t *testing.T) {
	source, destination := openAuditTest(t), openAuditTest(t)
	ctx := t.Context()
	details := string(bytes.Repeat([]byte("x"), maxRestoreBatchBytes+128))
	if err := source.Save([]Record{{Kind: "hallazgo", Time: Now(), Title: "Lote extenso", Details: details}}); err != nil {
		t.Fatal(err)
	}
	eventCount := 2*maxRestoreBatchRows + 7
	if _, err := source.db.ExecContext(ctx, `UPDATE pavarotti_audit_heads SET position = $2 WHERE expediente = $1`,
		source.expediente, eventCount); err != nil {
		t.Fatal(err)
	}
	if _, err := source.db.ExecContext(ctx, `
		INSERT INTO pavarotti_audit_events (expediente, position, actor, source, action, target, details)
		SELECT $1, position, 'prueba', 'postgres', $3, '', '{}'::jsonb
		FROM generate_series(2, $2::integer) AS series(position)`, source.expediente, eventCount, AuditEvidence); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	summary, err := source.BackupCase(ctx, &archive)
	if err != nil || summary.Rows["audit_event"] != eventCount {
		t.Fatalf("respaldo: %+v, %v", summary, err)
	}
	if _, err := destination.RestoreCase(ctx, bytes.NewReader(archive.Bytes()[:archive.Len()-1])); !errors.Is(err, ErrBackupIntegrity) {
		t.Fatalf("copia interrumpida: %v", err)
	}
	if records, err := destination.Records(); err != nil || len(records) != 0 {
		t.Fatalf("evidencia parcial: %d, %v", len(records), err)
	}
	if page, err := destination.AuditPage(ctx, 0, 50); err != nil || len(page.Events) != 0 {
		t.Fatalf("actividad parcial: %+v, %v", page, err)
	}
	restored, err := destination.RestoreCase(ctx, bytes.NewReader(archive.Bytes()))
	if err != nil || !reflect.DeepEqual(summary, restored) {
		t.Fatalf("restauración: %+v, %v", restored, err)
	}
	records, err := destination.Records()
	if err != nil || len(records) != 1 || records[0].Details != details {
		t.Fatalf("contenido del lote extenso: %d, %v", len(records), err)
	}
	if page, err := destination.AuditPage(ctx, 0, 2); err != nil || len(page.Events) != 2 ||
		page.Events[0].Position != int64(eventCount+1) || page.Events[0].Action != AuditRestore ||
		page.Events[1].Position != int64(eventCount) {
		t.Fatalf("secuencia restaurada: %+v, %v", page, err)
	}
}

func backupTestNote(t *testing.T, store *Store, title string) string {
	t.Helper()
	if err := store.Save([]Record{{Kind: "nota", Time: Now(), Title: title, Details: "Primera revisión"}}); err != nil {
		t.Fatal(err)
	}
	page, err := store.Page(t.Context(), PageRequest{Kind: "nota", Limit: 1})
	if err != nil || len(page.Rows) != 1 {
		t.Fatalf("nota de prueba: %+v, %v", page, err)
	}
	return page.Rows[0].ID
}

type backupTestWriter struct {
	io.Writer
	firstWrite func() error
}

func (writer *backupTestWriter) Write(p []byte) (int, error) {
	if writer.firstWrite != nil {
		firstWrite := writer.firstWrite
		writer.firstWrite = nil
		if err := firstWrite(); err != nil {
			return 0, err
		}
	}
	return writer.Writer.Write(p)
}

type backupTestReader struct {
	io.Reader
	started chan struct{}
	resume  <-chan struct{}
}

func (reader *backupTestReader) Read(p []byte) (int, error) {
	if reader.started != nil {
		close(reader.started)
		reader.started = nil
		<-reader.resume
	}
	return reader.Reader.Read(p)
}
