package analisis

import (
	"fmt"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"pavarotti/internal/caso"
)

func seedHTTPComparison(tb testing.TB, store *caso.Store, size int) (string, string) {
	tb.Helper()
	const batchSize = 1000
	first := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	day := first
	for start := 0; start < size; start += batchSize {
		day = first.AddDate(0, 0, start/batchSize)
		records := make([]caso.Record, min(batchSize, size-start))
		for index := range records {
			kind := "archivo HAR"
			if index%2 == 1 {
				kind = "tráfico"
			}
			status := [...]int{200, 204, 302, 403, 502}[index%5]
			record := caso.Record{Kind: kind, Time: day.Add(time.Duration(index) * time.Second).Format(time.RFC3339Nano),
				Title: fmt.Sprintf("GET %d", status), Source: fmt.Sprintf("https://host-%d.example.invalid", index%8),
				Traffic: &caso.Traffic{Method: "GET", Status: status, Type: "text/html"}, HTTPRuleSet: 1}
			if index%8 == 1 {
				record.HTTPFindings = []caso.HTTPFinding{{Rule: "nosniff-ausente", Label: "Falta nosniff"}}
			}
			records[index] = record
		}
		if err := store.Save(records); err != nil {
			tb.Fatal(err)
		}
	}
	return first.Format(time.DateOnly), day.Format(time.DateOnly)
}

func BenchmarkHTTPComparisonScale(b *testing.B) {
	for _, backend := range []string{"local", "postgres"} {
		b.Run(backend, func(b *testing.B) {
			for _, size := range []int{1000, 10000, 50000} {
				b.Run(fmt.Sprint(size), func(b *testing.B) {
					store := openScaleStore(b, backend)
					first, last := seedHTTPComparison(b, store, size)
					narrow := HTTPCompareCriteria{
						Baseline: HTTPWindow{Origin: "https://host-0.example.invalid", Capture: "har", From: first, To: first},
						Current:  HTTPWindow{Origin: "https://host-1.example.invalid", Capture: "proxy", From: last, To: last},
					}
					wide := HTTPCompareCriteria{
						Baseline: HTTPWindow{Capture: "har", From: first, To: last},
						Current:  HTTPWindow{Capture: "proxy", From: first, To: last},
					}
					for _, test := range []struct {
						name     string
						criteria HTTPCompareCriteria
						count    int
					}{{"acotada", narrow, 125}, {"amplia", wide, size / 2}} {
						b.Run(test.name, func(b *testing.B) {
							if _, err := CompareHTTP(b.Context(), store, test.criteria); err != nil {
								b.Fatal(err)
							}
							b.ReportAllocs()
							for b.Loop() {
								report, err := CompareHTTP(b.Context(), store, test.criteria)
								if err != nil || report.Baseline.Observations != test.count || report.Current.Observations != test.count {
									b.Fatalf("capturas A/B: %d/%d, %v", report.Baseline.Observations, report.Current.Observations, err)
								}
							}
						})
					}
				})
			}
		})
	}
}

func BenchmarkConcurrentHTTPComparisons(b *testing.B) {
	for _, backend := range []string{"local", "postgres"} {
		b.Run(backend, func(b *testing.B) {
			store := openScaleStore(b, backend)
			first, last := seedHTTPComparison(b, store, HTTPComparisonRecordLimit)
			windows := [2]HTTPCompareCriteria{
				{Baseline: HTTPWindow{Origin: "https://host-0.example.invalid", Capture: "har", From: first, To: first},
					Current: HTTPWindow{Origin: "https://host-1.example.invalid", Capture: "proxy", From: last, To: last}},
				{Baseline: HTTPWindow{Capture: "har", From: first, To: last}, Current: HTTPWindow{Capture: "proxy", From: first, To: last}},
			}
			expected := [2]int{125, HTTPComparisonRecordLimit / 2}
			var hashes [2]string
			for index, criteria := range windows {
				report, err := CompareHTTP(b.Context(), store, criteria)
				if err != nil || report.Baseline.Observations != expected[index] || report.Current.Observations != expected[index] {
					b.Fatalf("periodos de control: %d/%d, %v", report.Baseline.Observations, report.Current.Observations, err)
				}
				hashes[index] = report.InputSHA256
			}
			samples := [2][]time.Duration{make([]time.Duration, (b.N+1)/2), make([]time.Duration, b.N/2)}
			var next atomic.Int64
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					index := int(next.Add(1) - 1)
					kind := index % 2
					started := time.Now()
					report, err := CompareHTTP(b.Context(), store, windows[kind])
					samples[kind][index/2] = time.Since(started)
					if err != nil || report.InputSHA256 != hashes[kind] {
						b.Errorf("resultado concurrente con huella %s: %v", report.InputSHA256, err)
						return
					}
				}
			})
			b.StopTimer()
			for kind, durations := range samples {
				if len(durations) != 0 {
					slices.Sort(durations)
					p95 := (95*len(durations)+99)/100 - 1
					label := [2]string{"acotada-p95-ms", "amplia-p95-ms"}[kind]
					b.ReportMetric(float64(durations[p95])/float64(time.Millisecond), label)
				}
			}
		})
	}
}
