package caso

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sync"
	"testing"
)

func TestWatchlistsKeepConcurrentChanges(t *testing.T) {
	for _, backend := range []string{"local", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			var store *Store
			if backend == "postgres" {
				store = openAuditTest(t)
			} else {
				var err error
				store, err = Open(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { store.Close() })
			}
			const name = "Rastreo de guardia"
			watchChange(t, store, " "+name+" ", WatchCreate, Indicator{}, true)
			watchChange(t, store, name, WatchCreate, Indicator{}, false)
			watchChange(t, store, "Control", WatchCreate, Indicator{}, true)
			for _, invalid := range []string{"", "..", "a/b", "a\\b", "a\nb"} {
				if _, err := store.ChangeWatchlist(ctx, invalid, WatchCreate, Indicator{}); !errors.Is(err, ErrWatchlist) {
					t.Fatalf("nombre inválido %q: %v", invalid, err)
				}
			}
			var group sync.WaitGroup
			for index := 1; index <= 12; index++ {
				group.Go(func() {
					asset := Indicator{Type: "ipv4", Value: fmt.Sprintf("192.0.2.%d", index)}
					if changed, err := store.ChangeWatchlist(ctx, name, WatchAdd, asset); err != nil || !changed {
						t.Errorf("cambio %d: %t, %v", index, changed, err)
					}
				})
			}
			group.Wait()
			first := Indicator{Type: "ipv4", Value: "192.0.2.1"}
			watchChange(t, store, name, WatchAdd, first, false)
			watchChange(t, store, name, WatchRemove, first, true)
			watchChange(t, store, name, WatchRemove, first, false)
			watchChange(t, store, "Control", WatchDelete, Indicator{}, true)
			watchChange(t, store, "Control", WatchDelete, Indicator{}, false)
			if _, err := store.ChangeWatchlist(ctx, "Control", WatchAdd, first); !errors.Is(err, ErrWatchlistAbsent) {
				t.Fatalf("cambio en lista ausente: %v", err)
			}
			reopened := store
			if backend == "local" {
				var err error
				reopened, err = Open(store.path)
				if err != nil {
					t.Fatal(err)
				}
				defer reopened.Close()
			}
			lists, err := reopened.Watchlists(ctx)
			if err != nil || !reflect.DeepEqual(lists, []WatchlistSummary{{Name: name, Count: 11}}) {
				t.Fatalf("listas: %+v, %v", lists, err)
			}
			list, err := reopened.Watchlist(ctx, name)
			if err != nil || len(list.Assets) != 11 || list.Assets[0].Value != "192.0.2.10" ||
				list.Assets[10].Value != "192.0.2.9" {
				t.Fatalf("activos guardados: %+v, %v", list, err)
			}
			if backend == "postgres" {
				other := openAuditTest(t)
				empty, err := other.Watchlists(ctx)
				if err != nil || len(empty) != 0 {
					t.Fatalf("otro expediente: %+v, %v", empty, err)
				}
				audit, err := store.AuditPage(ctx, 0, 100)
				if err != nil || len(audit.Events) != 16 || audit.Events[0].Action != AuditWatchlist ||
					audit.Events[0].Details.Status != string(WatchDelete) {
					t.Fatalf("actividad: %d, %v", len(audit.Events), err)
				}
			}
		})
	}
}

func TestWatchlistMigrationAndBackup(t *testing.T) {
	destination := openAuditTest(t)
	restoreDSN := os.Getenv("PAVAROTTI_TEST_POSTGRES_RESTORE")
	if restoreDSN == "" {
		restoreDSN = os.Getenv("PAVAROTTI_TEST_POSTGRES")
	}
	restored := openAuditTestAt(t, restoreDSN)
	ctx := t.Context()
	var legacy bytes.Buffer
	old, err := destination.BackupCase(ctx, &legacy)
	if err != nil || old.Version != 1 {
		t.Fatalf("respaldo v1: %+v, %v", old, err)
	}
	if summary, err := InspectCaseBackup(ctx, bytes.NewReader(legacy.Bytes())); err != nil || !reflect.DeepEqual(summary, old) {
		t.Fatalf("validación v1: %+v, %v", summary, err)
	}
	folder := t.TempDir()
	local, err := Open(folder)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	const list = "Guardia DNS"
	asset := Indicator{Type: "dominio", Value: "host.example.invalid"}
	watchChange(t, local, list, WatchCreate, Indicator{}, true)
	watchChange(t, local, list, WatchAdd, asset, true)
	watchChange(t, destination, "Guardia anterior", WatchCreate, Indicator{}, true)
	if _, err := destination.ImportLocal(folder); err != nil {
		t.Fatal(err)
	}
	if _, err := destination.ImportLocal(folder); err != nil {
		t.Fatal(err)
	}
	watchChange(t, local, list, WatchAdd, Indicator{Type: "sha1", Value: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, true)
	if err := local.Save([]Record{{Kind: "nota", Title: "Debe quedar fuera del destino", Time: Now()}}); err != nil {
		t.Fatal(err)
	}
	if _, err := destination.ImportLocal(folder); !errors.Is(err, ErrMigrationConflict) {
		t.Fatalf("conflicto: %v", err)
	}
	if rows, err := destination.Records(); err != nil || len(rows) != 0 {
		t.Fatalf("migración parcial: %+v, %v", rows, err)
	}
	var archive bytes.Buffer
	summary, err := destination.BackupCase(ctx, &archive)
	if err != nil || summary.Version != 2 || summary.Rows[backupWatchlists] != 1 || summary.Rows["audit_event"] != 2 {
		t.Fatalf("respaldo v2: %+v, %v", summary, err)
	}
	if _, err := restored.RestoreCase(ctx, bytes.NewReader(archive.Bytes())); err != nil {
		t.Fatal(err)
	}
	lists, err := restored.Watchlists(ctx)
	if err != nil || !reflect.DeepEqual(lists, []WatchlistSummary{{Name: "Guardia DNS", Count: 1}, {Name: "Guardia anterior", Count: 0}}) {
		t.Fatalf("listas restauradas: %+v, %v", lists, err)
	}
	item, err := restored.Watchlist(ctx, list)
	if err != nil || !reflect.DeepEqual(item.Assets, []Indicator{asset}) {
		t.Fatalf("activos restaurados: %+v, %v", item, err)
	}
}

func watchChange(t *testing.T, store *Store, name string, action WatchAction, asset Indicator, expected bool) {
	t.Helper()
	changed, err := store.ChangeWatchlist(t.Context(), name, action, asset)
	if err != nil || changed != expected {
		t.Fatalf("%s en %q: %t, %v", action, name, changed, err)
	}
}
