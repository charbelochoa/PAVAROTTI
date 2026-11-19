package caso

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestAnalysisQueueRecovery(t *testing.T) {
	dsn := os.Getenv("PAVAROTTI_TEST_POSTGRES")
	if dsn == "" {
		t.Skip("PAVAROTTI_TEST_POSTGRES no configurado")
	}
	ctx := t.Context()
	expediente := "test-analysis-" + hex.EncodeToString(randBytes(t))
	open := func(name string) *Store {
		t.Helper()
		store, err := OpenPostgres(ctx, dsn, name)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		return store
	}
	first, second := open(expediente), open(expediente)
	other := open(expediente + "-otro")
	t.Cleanup(func() {
		if _, err := second.db.ExecContext(context.Background(), "DELETE FROM pavarotti_analysis_jobs WHERE expediente = $1", expediente); err != nil {
			t.Error(err)
		}
	})
	enqueue := func(source string, priority int) AnalysisJob {
		t.Helper()
		job, err := first.EnqueueAnalysis(ctx, Hash([]byte(source)), "1", priority, json.RawMessage(`{"records":[]}`))
		if err != nil {
			t.Fatal(err)
		}
		return job
	}
	claim := func(store *Store) AnalysisClaim {
		t.Helper()
		job, found, err := store.ClaimAnalysis(ctx, "1")
		if err != nil || !found {
			t.Fatalf("asignación: %t, %v", found, err)
		}
		return job
	}
	expire := func(id string) {
		t.Helper()
		if _, err := second.db.ExecContext(ctx, `UPDATE pavarotti_analysis_jobs SET lease_until = clock_timestamp() - interval '1 second'
			WHERE expediente = $1 AND id = $2`, expediente, id); err != nil {
			t.Fatal(err)
		}
	}
	low := enqueue("baja", 0)
	high := enqueue("alta", 1)
	promoted := enqueue("alta", 2)
	if promoted.ID != high.ID || promoted.Priority != 2 {
		t.Fatalf("la misma entrada debe reutilizar y promover la tarea: %+v", promoted)
	}
	if _, err := other.AnalysisJob(ctx, high.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("la tarea es visible fuera de su expediente: %v", err)
	}
	if _, found, err := other.ClaimAnalysis(ctx, "1"); err != nil || found {
		t.Fatalf("tarea asignada incorrectamente a otro expediente: %t, %v", found, err)
	}
	if _, err := first.CancelAnalysis(ctx, low.ID); err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		claim AnalysisClaim
		found bool
		err   error
	}
	results := make(chan outcome, 2)
	for _, handle := range []*Store{first, second} {
		go func(store *Store) {
			job, found, err := store.ClaimAnalysis(ctx, "1")
			results <- outcome{job, found, err}
		}(handle)
	}
	var crashed AnalysisClaim
	var count int
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.found {
			crashed = result.claim
			count++
		}
	}
	if count != 1 || crashed.Job.ID != high.ID || crashed.Job.Attempts != 1 {
		t.Fatalf("asignación inicial duplicada o incorrecta: %d, %+v", count, crashed)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	expire(high.ID)
	first = open(expediente)
	recovered := claim(first)
	if recovered.Job.ID != high.ID || recovered.Token == crashed.Token || recovered.Job.Attempts != 2 {
		t.Fatalf("recuperación: %+v", recovered)
	}
	if err := second.FinishAnalysis(ctx, crashed, json.RawMessage(`{"report":"obsoleto"}`), ""); !errors.Is(err, ErrJobState) {
		t.Fatalf("el ejecutor antiguo pudo confirmar un resultado: %v", err)
	}
	if err := first.RenewAnalysis(ctx, recovered); err != nil {
		t.Fatal(err)
	}
	if err := first.FinishAnalysis(ctx, recovered, json.RawMessage(`{"report":"recuperado"}`), ""); err != nil {
		t.Fatal(err)
	}
	completed, err := second.AnalysisJob(ctx, high.ID)
	var saved map[string]string
	if err != nil || completed.State != "succeeded" || json.Unmarshal(completed.Result, &saved) != nil || saved["report"] != "recuperado" {
		t.Fatalf("resultado persistido: %+v, %v", completed, err)
	}
	if got := enqueue("alta", 0); got.ID != high.ID || got.State != "succeeded" {
		t.Fatalf("la misma instantánea produjo otra tarea: %+v", got)
	}
	cancel := enqueue("cancelada", 1)
	running := claim(first)
	if running.Job.ID != cancel.ID {
		t.Fatal(running.Job)
	}
	if _, err := second.CancelAnalysis(ctx, cancel.ID); err != nil {
		t.Fatal(err)
	}
	if err := first.RenewAnalysis(ctx, running); !errors.Is(err, ErrJobState) {
		t.Fatalf("asignación cancelada renovable: %v", err)
	}
	if err := first.FinishAnalysis(ctx, running, json.RawMessage(`{}`), ""); !errors.Is(err, ErrJobState) {
		t.Fatalf("resultado publicado tras cancelar: %v", err)
	}
	exhausted := enqueue("agotada", 1)
	for attempt := 1; attempt <= AnalysisMaxAttempts; attempt++ {
		job := claim(first)
		if job.Job.ID != exhausted.ID || job.Job.Attempts != attempt {
			t.Fatalf("intento incorrecto: %+v", job.Job)
		}
		expire(exhausted.ID)
	}
	if _, found, err := first.ClaimAnalysis(ctx, "1"); err != nil || found {
		t.Fatalf("la cola excedió el límite de intentos: %t, %v", found, err)
	}
	failed, err := second.AnalysisJob(ctx, exhausted.ID)
	if err != nil || failed.State != "failed" || len(failed.Result) != 0 {
		t.Fatalf("estado al agotar intentos: %+v, %v", failed, err)
	}
	firstIn := enqueue("primera", 0)
	urgent := enqueue("urgente", 2)
	if got := claim(first); got.Job.ID != urgent.ID {
		t.Fatalf("se ignoró la prioridad: %+v", got.Job)
	}
	if got := claim(second); got.Job.ID != firstIn.ID {
		t.Fatalf("se reasignó una tarea todavía activa: %+v", got.Job)
	}
	old := enqueue("pendiente del ejecutor anterior", 2)
	newJob, err := second.EnqueueAnalysis(ctx, Hash([]byte("versión actual")), "2", 1, json.RawMessage(`{"records":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.EnqueueAnalysis(ctx, Hash([]byte("versión futura")), "3", 2, json.RawMessage(`{"records":[]}`)); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []AnalysisJob{old, newJob} {
		got, found, err := first.ClaimAnalysis(ctx, "2", "1")
		if err != nil || !found || got.Job.ID != expected.ID || got.Job.AgentVersion != expected.AgentVersion {
			t.Fatalf("prioridad entre versiones: %+v, %t, %v", got.Job, found, err)
		}
	}
}
