package analisis

import (
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"testing"
	"time"

	"pavarotti/internal/caso"
)

func BenchmarkAssetSourceCachePressure(b *testing.B) {
	for _, backend := range []string{"local", "postgres"} {
		b.Run(backend, func(b *testing.B) {
			open := openAssetPressureStore(b, backend)
			writer := open(b)
			query := AssetQuery{AssetKey: AssetKey{Type: "ipv6", Value: "2001:db8:ffff::42"}, Limit: 3}
			saveAssetPressureFixture(b, writer, query.AssetKey, 180000)
			expected := scanAssetPressureFixture(b, writer, query)
			if expected.Count != 6 || expected.Indicators != 1 || expected.Coverage != 2 || len(expected.Rows) != 8 {
				b.Fatalf("evidencia de control: %+v", expected)
			}
			verifier := open(b)
			verifyAssetPressurePages(b, verifier, query, expected)
			if err := verifier.Close(); err != nil {
				b.Fatal(err)
			}
			b.Run("primera", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					b.StopTimer()
					store := open(b)
					b.StartTimer()
					checkAssetPressurePage(b, store, query, expected, 0)
					b.StopTimer()
					if err := store.Close(); err != nil {
						b.Fatal(err)
					}
					b.StartTimer()
				}
			})
			b.Run("repetida", func(b *testing.B) {
				store := open(b)
				defer store.Close()
				checkAssetPressurePage(b, store, query, expected, 0)
				b.ReportAllocs()
				for b.Loop() {
					checkAssetPressurePage(b, store, query, expected, 0)
				}
			})
			if err := writer.Close(); err != nil {
				b.Fatal(err)
			}
		})
	}
}

func openAssetPressureStore(b *testing.B, backend string) func(*testing.B) *caso.Store {
	b.Helper()
	dsn := os.Getenv("PAVAROTTI_TEST_POSTGRES")
	if backend == "postgres" && dsn == "" {
		b.Skip("PAVAROTTI_TEST_POSTGRES no configurado")
	}
	folder, name := b.TempDir(), fmt.Sprintf("presion-indice-%d", time.Now().UnixNano())
	return func(b *testing.B) *caso.Store {
		b.Helper()
		var store *caso.Store
		var err error
		if backend == "local" {
			store, err = caso.Open(folder)
		} else {
			store, err = caso.OpenPostgres(b.Context(), dsn, name)
		}
		if err != nil {
			b.Fatal(err)
		}
		return store
	}
}

func saveAssetPressureFixture(b *testing.B, store *caso.Store, key AssetKey, count int) {
	b.Helper()
	const batchSize = 1000
	for start := 0; start < count; start += batchSize {
		batch := make([]caso.Record, min(count-start, batchSize))
		for index := range batch {
			position := start + index
			address := fmt.Sprintf("2001:db8:1::%x:%x", position>>16, position&0xffff)
			if position == 0 || position == count/3 || position == count*2/3 || position == count-1 {
				address = key.Value
			}
			owner := fmt.Sprintf("sensor-%06d.example.invalid", position)
			batch[index] = caso.Record{Kind: "dns", Title: "AAAA " + owner, Source: owner + ", " + address,
				SourceID: fmt.Sprintf("captura/respuesta/%d", position), Time: benchmarkAssetDay + "T09:00:00Z"}
		}
		if err := store.Save(batch); err != nil {
			b.Fatal(err)
		}
	}
	if err := store.Save([]caso.Record{
		{Kind: "indicador", Title: "Indicador confirmado", Indicator: &caso.Indicator{Type: key.Type, Value: key.Value}, Time: benchmarkAssetDay + "T10:30:00+01:00"},
		{Kind: "rdap", Title: "Rango RDAP", Network: "2001:db8:ffff::40 – 2001:db8:ffff::49", Time: benchmarkAssetDay + "T08:00:00Z"},
		{Kind: "stix", Title: "Prefijo STIX", Network: "2001:db8:ffff::/48", Time: benchmarkAssetDay + "T07:00:00Z"},
		{Kind: "nota", Title: "Referencia inicial", Source: "2001:db8:ffff::72", Time: benchmarkAssetDay + "T10:00:00Z"},
	}); err != nil {
		b.Fatal(err)
	}
	ctx := b.Context()
	notes, err := store.Page(ctx, caso.PageRequest{Kind: "nota", Limit: 1})
	if err != nil || len(notes.Rows) != 1 {
		b.Fatalf("nota de prueba: %d, %v", len(notes.Rows), err)
	}
	if _, err := store.EditContext(ctx, notes.Rows[0].ID, 1, "Referencia revisada", key.Value, "Se comprobó el origen"); err != nil {
		b.Fatal(err)
	}
}

func scanAssetPressureFixture(tb testing.TB, store *caso.Store, query AssetQuery) AssetDetail {
	tb.Helper()
	result := AssetDetail{AssetRow: AssetRow{AssetKey: query.AssetKey}}
	address, _ := netip.ParseAddr(query.Value)
	var sources []orderedAssetSource
	if err := store.Walk(tb.Context(), func(record caso.Record) error {
		role, network := assetSource(record, query.AssetKey, address)
		if role == "" {
			return nil
		}
		if role == "cobertura" {
			result.Coverage++
		} else {
			result.add(role)
		}
		sources = append(sources, orderedAssetSource{position: assetSourcePosition(record),
			source: AssetReference{Evidence: reference(record), Role: role, Network: network}})
		return nil
	}); err != nil {
		tb.Fatal(err)
	}
	slices.SortFunc(sources, func(a, b orderedAssetSource) int { return compareAssetSourcePositions(a.position, b.position) })
	for _, source := range sources {
		result.Rows = append(result.Rows, source.source)
	}
	return result
}

func verifyAssetPressurePages(tb testing.TB, store *caso.Store, query AssetQuery, expected AssetDetail) {
	tb.Helper()
	for start := 0; start < len(expected.Rows); start += query.Limit {
		query.After = ""
		if start > 0 {
			query.After = expected.Rows[start-1].ID
		}
		checkAssetPressurePage(tb, store, query, expected, start)
		for _, row := range expected.Rows[start:min(start+query.Limit, len(expected.Rows))] {
			got, err := store.RecordRevision(tb.Context(), row.ID, row.Revision)
			if err != nil || reference(got) != row.Evidence {
				tb.Fatalf("cita %s revisión %d: %+v, %v", row.ID, row.Revision, got, err)
			}
		}
	}
}

func checkAssetPressurePage(tb testing.TB, store *caso.Store, query AssetQuery, expected AssetDetail, start int) {
	tb.Helper()
	end := min(start+query.Limit, len(expected.Rows))
	if end < len(expected.Rows) {
		expected.Next = expected.Rows[end-1].ID
	}
	expected.Rows = expected.Rows[start:end]
	got, err := DescribeAsset(tb.Context(), store, query)
	if err != nil || !reflect.DeepEqual(got, expected) {
		tb.Fatalf("ficha en %d: %+v, esperado %+v, error %v", start, got, expected, err)
	}
}
