package analisis

import (
	"reflect"
	"testing"
)

func BenchmarkDenseAssetPages(b *testing.B) {
	for _, backend := range []string{"local", "postgres"} {
		b.Run(backend, func(b *testing.B) {
			const observations = 50000
			store := openScaleStore(b, backend)
			saveAssetScaleFixture(b, store, observations)
			inventory := AssetQuery{Limit: 50}
			first, err := ListAssets(b.Context(), store, inventory)
			if err != nil || len(first.Rows) != inventory.Limit || first.Rows[0].Count != observations || first.Next == "" {
				b.Fatalf("inventario: %d filas, %v", len(first.Rows), err)
			}
			inventory.After = first.Next
			second, err := ListAssets(b.Context(), store, inventory)
			if err != nil || len(second.Rows) != inventory.Limit || second.Next == "" ||
				compareAssetKeys(first.Rows[len(first.Rows)-1].AssetKey, second.Rows[0].AssetKey) >= 0 {
				b.Fatalf("segunda página del inventario: %d filas, %v", len(second.Rows), err)
			}
			query := AssetQuery{AssetKey: first.Rows[0].AssetKey, Limit: 50}
			expected := scanAssetPressureFixture(b, store, query)
			if expected.Count != observations || len(expected.Rows) != observations {
				b.Fatalf("observaciones: %d", expected.Count)
			}
			checkAssetPressurePage(b, store, query, expected, 0)
			start := 2 * query.Limit
			query.After = expected.Rows[start-1].ID
			checkAssetPressurePage(b, store, query, expected, start)
			citation := expected.Rows[start]
			original, err := store.RecordRevision(b.Context(), citation.ID, citation.Revision)
			if err != nil || reference(original) != citation.Evidence {
				b.Fatalf("cita %s: %v", citation.ID, err)
			}
			b.Run("inventario", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					result, err := ListAssets(b.Context(), store, inventory)
					if err != nil || !reflect.DeepEqual(result, second) {
						b.Fatalf("inventario: %d filas, %v", len(result.Rows), err)
					}
				}
			})
			b.Run("ficha", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					checkAssetPressurePage(b, store, query, expected, start)
				}
			})
		})
	}
}
