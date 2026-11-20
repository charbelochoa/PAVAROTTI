package caso

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

func TestLocalHTTPReadsSnapshotDuringImport(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	initial := Record{Kind: "archivo HAR", Title: "Captura original", Traffic: &Traffic{Status: 200}}
	if err := store.Save([]Record{initial}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	active := make(chan struct{})
	resume := make(chan struct{})
	finished := make(chan error, 1)
	var original []string
	go func() {
		finished <- store.WalkHTTP(ctx, func(record Record) error {
			original = append(original, record.Title)
			if len(original) == 1 {
				close(active)
				select {
				case <-resume:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		})
	}()
	select {
	case <-active:
	case err := <-finished:
		t.Fatalf("consulta inicial terminó antes de empezar: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	added := initial
	added.Title = "Segunda captura"
	if result, err := store.SaveEvidence(ctx, []Record{added}); err != nil || result.Imported != 1 {
		t.Fatalf("importación durante la lectura: %+v, %v", result, err)
	}
	var current []string
	if err := store.WalkHTTP(ctx, func(record Record) error {
		current = append(current, record.Title)
		return nil
	}); err != nil || len(current) != 2 || !slices.Contains(current, added.Title) {
		t.Fatalf("consulta posterior: %v, %v", current, err)
	}
	close(resume)
	select {
	case err := <-finished:
		if err != nil || !slices.Equal(original, []string{initial.Title}) {
			t.Fatalf("instantánea anterior: %v, %v", original, err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestPostgresCanceledHTTPWalkReleasesQuery(t *testing.T) {
	store := openAuditTest(t)
	store.db.SetMaxOpenConns(1)
	timeout, stop := context.WithTimeout(t.Context(), 5*time.Second)
	defer stop()
	capture := Record{Kind: "archivo HAR", Title: "Consulta activa", Traffic: &Traffic{Status: 200}}
	if _, err := store.SaveEvidence(timeout, []Record{capture}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(timeout)
	defer cancel()
	active, finished := make(chan struct{}), make(chan error, 1)
	go func() {
		finished <- store.WalkHTTP(ctx, func(Record) error {
			close(active)
			<-ctx.Done()
			return ctx.Err()
		})
	}()
	select {
	case <-active:
	case err := <-finished:
		t.Fatalf("consulta inicial terminó antes de empezar: %v", err)
	case <-timeout.Done():
		t.Fatal(timeout.Err())
	}
	cancel()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) || store.db.Stats().InUse != 0 {
			t.Fatalf("consulta cancelada con conexiones ocupadas %d: %v", store.db.Stats().InUse, err)
		}
	case <-timeout.Done():
		t.Fatal(timeout.Err())
	}
	count := 0
	if err := store.WalkHTTP(timeout, func(Record) error { count++; return nil }); err != nil || count != 1 {
		t.Fatalf("consulta después de cancelar: %d capturas, %v", count, err)
	}
}
