package analisis

import (
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"

	"pavarotti/internal/caso"
)

const benchmarkAssetDay = "2026-06-01"

var benchmarkAssetKeys = []AssetKey{
	{Type: "ipv4", Value: "192.0.2.42"},
	{Type: "red", Value: "192.0.2.40 – 192.0.2.49"},
	{Type: "red", Value: "192.0.2.32/27"},
}

func saveAssetScaleFixture(tb testing.TB, store *caso.Store, size int) {
	tb.Helper()
	const batchSize = 1000
	first, _ := time.Parse(time.DateOnly, benchmarkAssetDay)
	for start := 0; start < size; start += batchSize {
		stamp := first.AddDate(0, 0, start/batchSize)
		batch := make([]caso.Record, min(batchSize, size-start))
		for index := range batch {
			position := start + index
			address := netip.AddrFrom4([4]byte{198, 18, byte(position >> 8), byte(position)})
			batch[index] = caso.Record{Kind: "dns", Title: "A activo.example.invalid", Source: "activo.example.invalid, " + address.String(),
				SourceID: fmt.Sprintf("paquete/respuesta/%d", position), Time: stamp.Add(time.Duration(index) * time.Second).Format(time.RFC3339Nano)}
		}
		if err := store.Save(batch); err != nil {
			tb.Fatal(err)
		}
	}
	if err := store.Save([]caso.Record{
		{Kind: "rdap", Title: "Rango RDAP", Network: benchmarkAssetKeys[1].Value, Time: benchmarkAssetDay + "T08:00:00Z"},
		{Kind: "stix", Title: "Prefijo STIX", Network: benchmarkAssetKeys[2].Value, Time: benchmarkAssetDay + "T10:00:00Z"},
		{Kind: "dns", Title: "A host.example.invalid", Source: "host.example.invalid, 192.0.2.42", SourceID: "dns/respuesta/1", Time: benchmarkAssetDay + "T12:00:00Z"},
		{Kind: "archivo HAR", Title: "GET 200", Source: "https://192.0.2.58", Traffic: &caso.Traffic{Status: 200}, Time: benchmarkAssetDay + "T12:00:01Z"},
		{Kind: "indicador", Title: "Indicador", Indicator: &caso.Indicator{Type: "ipv4", Value: "192.0.2.42"}, Time: benchmarkAssetDay + "T13:00:00Z"},
	}); err != nil {
		tb.Fatal(err)
	}
}

func BenchmarkAssetScale(b *testing.B) {
	for _, backend := range []string{"local", "postgres"} {
		b.Run(backend, func(b *testing.B) {
			for _, size := range []int{1000, 50000} {
				b.Run(fmt.Sprint(size), func(b *testing.B) {
					store := openScaleStore(b, backend)
					saveAssetScaleFixture(b, store, size)
					b.Run("inventario", func(b *testing.B) {
						query := AssetQuery{Limit: 50}
						b.ReportAllocs()
						for b.Loop() {
							result, err := ListAssets(b.Context(), store, query)
							if err != nil || len(result.Rows) != 50 || result.Rows[0].Count != size || result.Next == "" {
								b.Fatalf("inventario: %d filas, %v", len(result.Rows), err)
							}
						}
					})
					for _, test := range []struct {
						name                           string
						index, direct, covers, members int
					}{{"ip", 0, 2, 2, 0}, {"rdap", 1, 1, 0, 1}, {"stix", 2, 1, 0, 2}} {
						key := benchmarkAssetKeys[test.index]
						b.Run("ficha_"+test.name, func(b *testing.B) {
							b.ReportAllocs()
							for b.Loop() {
								result, err := DescribeAsset(b.Context(), store, AssetQuery{AssetKey: key})
								if err != nil || result.Count != test.direct || result.Coverage != test.covers {
									b.Fatalf("ficha: %d fuentes directas, %d coberturas, %v", result.Count, result.Coverage, err)
								}
							}
						})
						b.Run("cobertura_"+test.name, func(b *testing.B) {
							criteria := AssetCoverageCriteria{AssetKey: key, From: benchmarkAssetDay, To: benchmarkAssetDay}
							if _, err := CoverAsset(b.Context(), store, criteria); err != nil {
								b.Fatal(err)
							}
							b.ReportAllocs()
							for b.Loop() {
								result, err := CoverAsset(b.Context(), store, criteria)
								if err != nil || result.Direct != test.direct || result.Coverage != test.covers || result.Addresses != test.members {
									b.Fatalf("cobertura: %d fuentes, %d coberturas, %d miembros, %v", result.Direct, result.Coverage, result.Addresses, err)
								}
							}
						})
					}
				})
			}
		})
	}
}

func openScaleStore(tb testing.TB, backend string) *caso.Store {
	tb.Helper()
	var store *caso.Store
	var err error
	if backend == "local" {
		store, err = caso.Open(tb.TempDir())
	} else {
		dsn := os.Getenv("PAVAROTTI_TEST_POSTGRES")
		if dsn == "" {
			tb.Skip("PAVAROTTI_TEST_POSTGRES no configurado")
		}
		store, err = caso.OpenPostgres(tb.Context(), dsn, fmt.Sprintf("escala-%d", time.Now().UnixNano()))
	}
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = store.Close() })
	return store
}

func BenchmarkConcurrentAssetSources(b *testing.B) {
	for _, backend := range []string{"local", "postgres"} {
		b.Run(backend, func(b *testing.B) {
			store := openScaleStore(b, backend)
			saveAssetScaleFixture(b, store, 50000)
			query := AssetQuery{AssetKey: benchmarkAssetKeys[0], Limit: 2}
			check := func(b *testing.B) bool {
				detail, err := DescribeAsset(b.Context(), store, query)
				if err != nil || detail.Count != 2 || detail.Coverage != 2 || len(detail.Rows) != 2 || detail.Next == "" {
					b.Errorf("fuentes directas %d, coberturas %d, filas %d, error %v", detail.Count, detail.Coverage, len(detail.Rows), err)
					return false
				}
				return true
			}
			if !check(b) {
				return
			}
			b.Run("una", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if !check(b) {
						return
					}
				}
			})
			b.Run("paralelas", func(b *testing.B) {
				b.ReportAllocs()
				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						if !check(b) {
							return
						}
					}
				})
			})
		})
	}
}
