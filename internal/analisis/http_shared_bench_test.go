package analisis

import (
	"fmt"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"pavarotti/internal/caso"
)

func BenchmarkHTTPComparisonAcrossCases(b *testing.B) {
	type comparison struct {
		name     string
		store    *caso.Store
		criteria HTTPCompareCriteria
		expected HTTPComparison
	}
	var cases [4]comparison
	for index := range cases {
		store := openScaleStore(b, "postgres")
		first, last := seedHTTPComparisonForCase(b, store, HTTPComparisonRecordLimit, fmt.Sprintf(" · Expediente %d", index+1))
		criteria := HTTPCompareCriteria{
			Baseline: HTTPWindow{Capture: "har", From: first, To: last},
			Current:  HTTPWindow{Capture: "proxy", From: first, To: last},
		}
		name, count := "amplia", HTTPComparisonRecordLimit/2
		if index%2 == 0 {
			name, count = "acotada", 125
			criteria.Baseline.Origin, criteria.Baseline.To = "https://host-0.example.invalid", first
			criteria.Current.Origin, criteria.Current.From = "https://host-1.example.invalid", last
		}
		result, err := CompareHTTP(b.Context(), store, criteria)
		if err != nil || result.Baseline.Observations != count || result.Current.Observations != count {
			b.Fatalf("expediente %d: %d/%d observaciones, %v", index+1, result.Baseline.Observations, result.Current.Observations, err)
		}
		for _, previous := range cases[:index] {
			if previous.expected.InputSHA256 == result.InputSHA256 {
				b.Fatalf("expedientes con la misma huella: %s", result.InputSHA256)
			}
		}
		cases[index] = comparison{fmt.Sprintf("%d-%s", index+1, name), store, criteria, result}
	}
	for _, mode := range []string{"secuencial", "simultanea"} {
		b.Run(mode, func(b *testing.B) {
			var samples [len(cases)][]time.Duration
			run := func(index int) {
				item := cases[index]
				started := time.Now()
				result, err := CompareHTTP(b.Context(), item.store, item.criteria)
				samples[index] = append(samples[index], time.Since(started))
				if err != nil || !reflect.DeepEqual(result, item.expected) {
					b.Errorf("expediente %s: huella %s, %v", item.name, result.InputSHA256, err)
				}
			}
			b.ReportAllocs()
			for b.Loop() {
				var workers sync.WaitGroup
				for index := range cases {
					if mode == "secuencial" {
						run(index)
					} else {
						workers.Go(func() { run(index) })
					}
				}
				workers.Wait()
			}
			for index, durations := range samples {
				slices.Sort(durations)
				median, p95 := durations[(len(durations)-1)/2], durations[(95*len(durations)+99)/100-1]
				b.ReportMetric(float64(median)/float64(time.Millisecond), cases[index].name+"-p50-ms")
				b.ReportMetric(float64(p95)/float64(time.Millisecond), cases[index].name+"-p95-ms")
			}
		})
	}
}
