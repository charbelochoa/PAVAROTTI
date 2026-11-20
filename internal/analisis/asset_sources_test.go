package analisis

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"pavarotti/internal/caso"
)

func TestSparseAssetSourcesSeeExternalChanges(t *testing.T) {
	for _, backend := range []string{"local", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			store, writer := openAssetSourcePair(t, backend)
			const address = "192.0.2.42"
			if err := writer.Save([]caso.Record{
				{Kind: "dns", Source: "host.example.invalid, ::ffff:c000:022a", SourceID: "pcap/1/respuesta/1", Time: "2026-06-01T12:00:00Z"},
				{Kind: "rdap", Title: "Red · 192.0.2.40 – 192.0.2.49", Time: "2026-06-01T11:00:00Z"},
				{Kind: "nota", Title: "Referencia anterior", Details: "Revisión original", Source: "192.0.2.58", Time: "2026-06-01T13:00:00Z"},
			}); err != nil {
				t.Fatal(err)
			}
			if err := writer.Save([]caso.Record{{Kind: "dns", Source: "192.0.2.5"}}); err != nil {
				t.Fatal(err)
			}
			ctx := t.Context()
			query := AssetQuery{AssetKey: AssetKey{Type: "ipv4", Value: address}, Limit: 2}
			before, err := DescribeAsset(ctx, store, query)
			if err != nil || before.Count != 1 || before.Coverage != 1 || len(before.Rows) != 2 || before.Rows[0].Kind != "dns" {
				t.Fatalf("ficha inicial: %+v, %v", before, err)
			}
			if repeat, err := DescribeAsset(ctx, store, query); err != nil || !reflect.DeepEqual(repeat, before) {
				t.Fatalf("ficha repetida: %+v, %v", repeat, err)
			}
			notes, err := writer.Page(ctx, caso.PageRequest{Kind: "nota"})
			if err != nil || len(notes.Rows) != 1 {
				t.Fatalf("nota editable: %+v, %v", notes, err)
			}
			id := notes.Rows[0].ID
			if _, err := writer.EditContext(ctx, id, 1, "Referencia actual", address, "Revisión actual"); err != nil {
				t.Fatal(err)
			}
			if err := writer.Save([]caso.Record{{Kind: "archivo HAR", Title: "GET 200", Source: "https://[::ffff:192.0.2.42]:444/registro",
				Time: "2026-06-01T15:00:00+01:00", Traffic: &caso.Traffic{Status: 200}}}); err != nil {
				t.Fatal(err)
			}
			var readers sync.WaitGroup
			for range 4 {
				readers.Go(func() {
					page, err := DescribeAsset(ctx, store, query)
					if err != nil || page.Count != 3 || page.Coverage != 1 || len(page.Rows) != 2 || page.Rows[0].Kind != "archivo HAR" ||
						page.Rows[1].ID != id || page.Rows[1].Revision != 2 || page.Next != id {
						t.Errorf("ficha tras importación y edición: %+v, %v", page, err)
						return
					}
					later := query
					later.After = page.Next
					rest, err := DescribeAsset(ctx, store, later)
					if err != nil || rest.Count != 3 || rest.Coverage != 1 || len(rest.Rows) != 2 ||
						!reflect.DeepEqual(rest.Rows, before.Rows) || rest.Next != "" {
						t.Errorf("fuentes tras el cursor: %+v, %v", rest, err)
					}
				})
			}
			readers.Wait()
			if _, err := writer.EditContext(ctx, id, 2, "Referencia retirada", "", "Ya no cita a la dirección"); err != nil {
				t.Fatal(err)
			}
			query.After = id
			if _, err := DescribeAsset(ctx, store, query); !errors.Is(err, ErrAssetQuery) {
				t.Fatalf("cursor que dejó de pertenecer al activo: %v", err)
			}
		})
	}
}

func openAssetSourcePair(t *testing.T, backend string) (*caso.Store, *caso.Store) {
	t.Helper()
	var open func() (*caso.Store, error)
	if backend == "local" {
		folder := t.TempDir()
		open = func() (*caso.Store, error) { return caso.Open(folder) }
	} else {
		dsn := os.Getenv("PAVAROTTI_TEST_POSTGRES")
		if dsn == "" {
			t.Skip("PAVAROTTI_TEST_POSTGRES no configurado")
		}
		name := fmt.Sprintf("fuentes-%d", time.Now().UnixNano())
		open = func() (*caso.Store, error) { return caso.OpenPostgres(t.Context(), dsn, name) }
	}
	var pair [2]*caso.Store
	for index := range pair {
		store, err := open()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		pair[index] = store
	}
	return pair[0], pair[1]
}
