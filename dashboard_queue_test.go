package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"pavarotti/internal/analisis"
	"pavarotti/internal/caso"
)

func TestAnalysisClaimProcess(t *testing.T) {
	expediente := os.Getenv("PAVAROTTI_TEST_LEASE_HOLDER")
	if expediente == "" {
		t.Skip("subproceso de la prueba de recuperación")
	}
	store, err := caso.OpenPostgres(t.Context(), os.Getenv("PAVAROTTI_TEST_POSTGRES"), expediente)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	claim, found, err := store.ClaimAnalysis(t.Context(), analisis.AgentVersion)
	if err != nil || !found {
		t.Fatalf("asignación del subproceso: %t, %v", found, err)
	}
	fmt.Println(claim.Job.ID)
	select {
	case <-t.Context().Done():
	case <-time.After(2 * caso.AnalysisLease):
		t.Fatal("el ejecutor de prueba no fue interrumpido")
	}
}

func TestAnalysisQueueProcessRecovery(t *testing.T) {
	dsn := os.Getenv("PAVAROTTI_TEST_POSTGRES")
	if dsn == "" {
		t.Skip("PAVAROTTI_TEST_POSTGRES no configurado")
	}
	var nonce [16]byte
	rand.Read(nonce[:])
	name := "test-worker-" + hex.EncodeToString(nonce[:])
	ctx, cancel := context.WithTimeout(t.Context(), caso.AnalysisLease+18*time.Second)
	defer cancel()
	open := func() *caso.Store {
		t.Helper()
		store, err := caso.OpenPostgres(ctx, dsn, name)
		if err != nil {
			t.Fatal(err)
		}
		return store
	}
	store := open()
	defer store.Close()
	t.Cleanup(func() {
		db, err := sql.Open("pgx", dsn)
		if err != nil {
			t.Error(err)
			return
		}
		defer db.Close()
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := db.ExecContext(cleanup, "DELETE FROM pavarotti_analysis_jobs WHERE expediente = $1", name); err != nil {
			t.Error(err)
		}
		if _, err := db.ExecContext(cleanup, "DELETE FROM pavarotti_evidence_batches WHERE expediente = $1", name); err != nil {
			t.Error(err)
		}
	})
	if err := store.Save([]caso.Record{{Kind: "nota", Time: caso.Now(), Title: "Fuente registrada", Source: "https://evidence.invalid"}}); err != nil {
		t.Fatal(err)
	}
	job, err := analisis.Enqueue(ctx, store, 1)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	process := exec.CommandContext(ctx, executable, "-test.run=^TestAnalysisClaimProcess$")
	process.Env = append(os.Environ(), "PAVAROTTI_TEST_LEASE_HOLDER="+name)
	stdout, err := process.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	process.Stderr = os.Stderr
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	fmtID := bufio.NewScanner(stdout)
	started := fmtID.Scan() && fmtID.Text() == job.ID
	if err := process.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = process.Wait()
	if !started {
		t.Fatal("el subproceso no confirmó la asignación antes de detenerse")
	}
	workerContext, stopWorkers := context.WithCancel(ctx)
	var workers []<-chan error
	for range 2 {
		handle := open()
		completed := make(chan error, 1)
		go func() {
			defer handle.Close()
			completed <- analisis.RunQueue(workerContext, handle)
		}()
		workers = append(workers, completed)
	}
	defer func() {
		stopWorkers()
		for _, done := range workers {
			if err := <-done; err != nil {
				t.Error(err)
			}
		}
	}()
	poll := time.NewTicker(250 * time.Millisecond)
	defer poll.Stop()
	for job.State != "succeeded" {
		select {
		case <-ctx.Done():
			t.Fatalf("la tarea no se recuperó: %+v", job)
		case <-poll.C:
			job, err = store.AnalysisJob(ctx, job.ID)
			if err != nil || job.State == "failed" {
				t.Fatalf("estado de la tarea: %+v, %v", job, err)
			}
		}
	}
	var report analisis.Report
	if err := json.Unmarshal(job.Result, &report); err != nil || job.Attempts != 2 || report.Records != 1 ||
		report.InputSHA256 != job.Fingerprint || len(report.Assets) != 1 || report.Assets[0].Value != "evidence.invalid" {
		t.Fatalf("informe recuperado: %+v, %+v, %v", job, report, err)
	}
	reused, err := analisis.Enqueue(ctx, store, 2)
	jobs, listErr := store.AnalysisJobs(ctx)
	if err != nil || listErr != nil || reused.ID != job.ID || reused.State != "succeeded" || len(jobs) != 1 {
		t.Fatalf("persistencia de un solo resultado: %+v, %v, %d, %v", reused, err, len(jobs), listErr)
	}
}
