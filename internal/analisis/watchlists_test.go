package analisis

import (
	"errors"
	"reflect"
	"testing"

	"pavarotti/internal/caso"
)

func TestWatchlistsCompareObservationsAndKeepLatestCitation(t *testing.T) {
	store, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := t.Context()
	const name = "Activos de guardia"
	change := func(raw AssetKey, action caso.WatchAction, expected bool) {
		t.Helper()
		changed, err := ChangeWatchlist(ctx, store, name, action, raw)
		if err != nil || changed != expected {
			t.Fatalf("seguimiento %s: %t, %v", action, changed, err)
		}
	}
	change(AssetKey{}, caso.WatchCreate, true)
	change(AssetKey{Type: "dominio", Value: " HOST.example.invalid. "}, caso.WatchAdd, true)
	change(AssetKey{Type: "dominio", Value: "host.example.invalid"}, caso.WatchAdd, false)
	change(AssetKey{Type: "ipv4", Value: "192.0.2.42"}, caso.WatchAdd, true)
	change(AssetKey{Type: "ipv4", Value: "192.0.2.99"}, caso.WatchAdd, true)
	change(AssetKey{Type: "red", Value: "192.0.2.43/27"}, caso.WatchAdd, true)
	if _, err := ChangeWatchlist(ctx, store, name, caso.WatchAdd, AssetKey{Type: "ipv4", Value: "host.invalid"}); !errors.Is(err, ErrAssetQuery) {
		t.Fatalf("activo inválido: %v", err)
	}
	if err := store.Save([]caso.Record{
		{Kind: "dns", Source: "host.example.invalid, 192.0.2.42", Time: "2026-06-01T13:00:00Z"},
		{Kind: "stix", Source: "192.0.2.42", Network: "192.0.2.32/27", Time: "2026-06-01T15:00:00Z"},
		{Kind: "rdap", Network: "192.0.2.40 – 192.0.2.49", Time: "2026-06-01T12:00:00Z"},
		{Kind: "nota", Title: "Nota citada", Source: "host.example.invalid", Time: "2026-06-01T18:35:00+05:30"},
		{Kind: "indicador", Indicator: &caso.Indicator{Type: "ipv4", Value: "192.0.2.42"}, Time: "2026-06-01T09:00:00Z"},
	}); err != nil {
		t.Fatal(err)
	}
	review, err := ReviewWatchlist(ctx, store, name)
	if err != nil || len(review.Rows) != 4 {
		t.Fatalf("revisión: %+v, %v", review, err)
	}
	for _, row := range review.Rows {
		card, err := DescribeAsset(ctx, store, AssetQuery{AssetKey: row.AssetKey})
		if row.Value == "192.0.2.99" {
			if row.Count != 0 || row.Coverage != 0 || row.Latest != nil || !errors.Is(err, caso.ErrNotFound) {
				t.Fatalf("activo pendiente: %+v, %v", row, err)
			}
			continue
		}
		if err != nil || row.AssetRow != card.AssetRow || row.Coverage != card.Coverage || !reflect.DeepEqual(row.Latest, &card.Rows[0]) {
			t.Fatalf("ficha y seguimiento distintos: %+v, %+v, %v", row, card, err)
		}
	}
	latest := review.Rows[0].Latest
	if latest.Kind != "nota" || latest.Revision != 1 || review.Rows[1].Coverage != 1 || review.Rows[1].Indicators != 1 {
		t.Fatalf("recuentos y citas: %+v", review.Rows)
	}
	if _, err := store.EditContext(ctx, latest.ID, 1, "Revisión de guardia", "host.example.invalid", "Nueva versión"); err != nil {
		t.Fatal(err)
	}
	updated, err := ReviewWatchlist(ctx, store, name)
	if err != nil || updated.Rows[0].Latest.Revision != 2 || updated.Rows[0].Count != review.Rows[0].Count {
		t.Fatalf("revisión vigente: %+v, %v", updated, err)
	}
	change(AssetKey{Type: "red", Value: "192.0.2.58/27"}, caso.WatchRemove, true)
}
