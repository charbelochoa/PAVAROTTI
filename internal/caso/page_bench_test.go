package caso

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func BenchmarkHistoryPages(b *testing.B) {
	for _, size := range []int{1000, 10000, 50000} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			store, err := Open(b.TempDir())
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() { _ = store.Close() })
			day := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
			for offset := 0; offset < size; offset += 1000 {
				stamp := day.AddDate(0, 0, offset/1000)
				batch := make([]Record, 1000)
				for index := range batch {
					address := offset + index + 1
					host := netip.AddrFrom4([4]byte{198, 18, byte(address >> 8), byte(address)})
					batch[index] = Record{Kind: "archivo HAR", Time: stamp.Add(time.Duration(index%60) * time.Second).Format(time.RFC3339Nano),
						Title: "GET 200", Source: "https://" + host.String(),
						Traffic: &Traffic{Method: "GET", Status: 200, Type: "text/html"}, Signals: []string{"HTTPS sin cabecera HSTS"},
						HTTPFindings: []HTTPFinding{{Rule: "hsts-ausente"}}}
				}
				if err := store.Save(batch); err != nil {
					b.Fatal(err)
				}
			}
			first, err := store.Page(b.Context(), PageRequest{Kind: "http"})
			if err != nil || len(first.Rows) != DefaultPageSize || first.Next == "" {
				b.Fatalf("primera página: %d, %v", len(first.Rows), err)
			}
			for _, target := range []struct {
				name  string
				query PageRequest
			}{
				{"primera", PageRequest{Kind: "http"}},
				{"siguiente", PageRequest{Kind: "http", After: first.Next}},
				{"dia_y_regla", PageRequest{Kind: "http", HTTPFrom: day.Format(time.DateOnly), HTTPTo: day.Format(time.DateOnly), HTTPRule: "hsts-ausente"}},
			} {
				b.Run(target.name, func(b *testing.B) {
					b.ReportAllocs()
					for b.Loop() {
						page, err := store.Page(b.Context(), target.query)
						if err != nil || len(page.Rows) != DefaultPageSize {
							b.Fatalf("página: %d, %v", len(page.Rows), err)
						}
					}
				})
			}
		})
	}
}
