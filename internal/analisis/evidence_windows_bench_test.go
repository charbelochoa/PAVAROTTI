package analisis

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"pavarotti/internal/caso"
)

func BenchmarkEvidenceWindows(b *testing.B) {
	for _, size := range []int{1000, 10000, 50000} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			store, err := caso.Open(b.TempDir())
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() { _ = store.Close() })
			const batchSize = 1000
			first := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
			for offset := 0; offset < size; offset += batchSize {
				stamp := first.AddDate(0, 0, offset/batchSize)
				batch := make([]caso.Record, batchSize)
				for index := range batch {
					position := offset + index + 1
					address := netip.AddrFrom4([4]byte{198, 18, byte(position >> 8), byte(position)})
					batch[index] = caso.Record{
						Kind: "archivo HAR", Time: stamp.Add(time.Duration(index%60) * time.Second).Format(time.RFC3339Nano),
						Title: "GET 200", Source: "https://" + address.String(),
						Traffic: &caso.Traffic{Method: "GET", Status: 200, Type: "text/html"}, HTTPRuleSet: 1,
						HTTPFindings: []caso.HTTPFinding{{Rule: "hsts-ausente", Label: "HTTPS sin cabecera HSTS"}},
					}
				}
				if err := store.Save(batch); err != nil {
					b.Fatal(err)
				}
			}
			day := first.Format(time.DateOnly)
			b.Run("comparacion_por_origen", func(b *testing.B) {
				window := HTTPWindow{Origin: "https://198.18.0.2", From: day, To: day}
				criteria := HTTPCompareCriteria{Baseline: window, Current: window}
				if _, err := CompareHTTP(b.Context(), store, criteria); err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				for b.Loop() {
					report, err := CompareHTTP(b.Context(), store, criteria)
					if err != nil || report.Baseline.Observations != 1 {
						b.Fatalf("comparación: %+v, %v", report.Baseline, err)
					}
				}
			})
			b.Run("cobertura_por_dia", func(b *testing.B) {
				criteria := AssetCoverageCriteria{AssetKey: AssetKey{Type: "red", Value: "198.18.0.0/15"}, From: day, To: day}
				if _, err := CoverAsset(b.Context(), store, criteria); err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				for b.Loop() {
					report, err := CoverAsset(b.Context(), store, criteria)
					if err != nil || report.Addresses != batchSize {
						b.Fatalf("cobertura: %d direcciones, %v", report.Addresses, err)
					}
				}
			})
		})
	}
}
