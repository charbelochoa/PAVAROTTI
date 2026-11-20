package analisis

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"pavarotti/internal/caso"
)

func TestHTTPComparisonUsesRecordedUTCWindows(t *testing.T) {
	store, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	finding := caso.HTTPFinding{Rule: "nosniff-ausente", Label: "Falta nosniff"}
	origin := "https://example.invalid"
	rows := []caso.Record{
		{Kind: "nota", Time: "2026-11-01T00:00:00Z", Title: "Nota"},
		{Kind: "archivo HAR", Time: "2026-10-31T18:00:00-06:00", Title: "HTML", Source: "https://EXAMPLE.INVALID:443",
			Traffic: &caso.Traffic{Status: 200}, HTTPRuleSet: 1, Signals: []string{finding.Label, finding.Label},
			HTTPFindings: []caso.HTTPFinding{finding, finding}},
		{Kind: "archivo HAR", Time: "2026-11-01T23:59:59.999999999Z", Title: "Cabeceras completas", Source: origin,
			Traffic: &caso.Traffic{Status: 204}, HTTPRuleSet: 1},
		{Kind: "archivo HAR", Time: "2026-11-01T05:00:00Z", Title: "Registro anterior", Source: origin,
			Traffic: &caso.Traffic{Status: 200}, Signals: []string{"Señal histórica", "Señal histórica"}},
		{Kind: "archivo HAR", Time: "2026-11-01T05:00:00Z", Title: "Otra aplicación", Source: origin + ":8443",
			Traffic: &caso.Traffic{Status: 200}, HTTPRuleSet: 1},
		{Kind: "archivo HAR", Time: "2026-11-01T12:00:00Z", Title: "Registro tipado anterior", Source: origin,
			Traffic: &caso.Traffic{Status: 200}, HTTPFindings: []caso.HTTPFinding{finding}},
		{Kind: "tráfico", Time: "2026-11-02T00:00:00Z", Title: "502 local", Source: origin,
			Traffic: &caso.Traffic{Status: 502}, Signals: []string{caso.ProxyNoResponseSignal}},
		{Kind: "tráfico", Time: "2026-11-02T01:00:00Z", Title: "502 del servidor", Source: origin,
			Traffic: &caso.Traffic{Status: 502}, HTTPRuleSet: 1},
		{Kind: "tráfico", Time: "2026-11-02T02:00:00Z", Title: "1xx", Source: origin,
			Traffic: &caso.Traffic{Status: 103}},
		{Kind: "tráfico", Time: "2026-11-03T00:00:00Z", Title: "Otro día", Source: origin,
			Traffic: &caso.Traffic{Status: 200}, HTTPRuleSet: 1},
	}
	saved, err := store.SaveEvidence(t.Context(), rows)
	if err != nil || saved.Imported != len(rows) {
		t.Fatalf("evidencia: %+v, %v", saved, err)
	}
	criteria := HTTPCompareCriteria{
		Baseline: HTTPWindow{Origin: "https://EXAMPLE.INVALID:0443/", Capture: "har", From: "2026-11-01", To: "2026-11-01"},
		Current:  HTTPWindow{Origin: origin, Capture: "proxy", From: "2026-11-02", To: "2026-11-02"},
	}
	report, err := CompareHTTP(t.Context(), store, criteria)
	if err != nil {
		t.Fatal(err)
	}
	if report.Schema != HTTPComparisonSchema || len(report.InputSHA256) != 64 || report.Criteria.Baseline.Origin != origin ||
		report.Criteria.Baseline.Capture != "archivo HAR" || report.Baseline != (HTTPWindowStats{Observations: 4, Responses: 4, Assessed: 2}) ||
		report.Current != (HTTPWindowStats{Observations: 3, Responses: 2, TransportFailures: 1, Assessed: 1}) {
		t.Fatalf("resumen: %+v", report)
	}
	byKey := make(map[string]HTTPCompareRow)
	for _, row := range report.Rows {
		byKey[row.Code] = row
	}
	rule := byKey[finding.Rule]
	if len(byKey) != 6 || byKey["2xx"].Baseline.Count != 4 || byKey["5xx"].Current.Count != 1 ||
		byKey["sin-respuesta"].Current.Count != 1 || byKey["Señal histórica"].Baseline.Count != 1 ||
		rule.Baseline.Count != 2 || len(rule.Baseline.Evidence) != 2 || rule.Current.Count != 0 {
		t.Fatalf("filas: %+v", report.Rows)
	}
	citation := rule.Baseline.Evidence[1]
	record, err := store.RecordRevision(t.Context(), citation.ID, citation.Revision)
	if err != nil || record.Title != "HTML" || citation.HTTPRule != finding.Rule || citation.Revision != 1 || citation.Origin != origin {
		t.Fatalf("cita: %+v, %v", citation, err)
	}
	criteria.Baseline.Origin = origin
	repeat, err := CompareHTTP(t.Context(), store, criteria)
	if err != nil || !reflect.DeepEqual(report, repeat) {
		t.Fatalf("resultado no determinista: %v, %s, %s", err, report.InputSHA256, repeat.InputSHA256)
	}
	criteria.Current = criteria.Baseline
	overlap, err := CompareHTTP(t.Context(), store, criteria)
	if err != nil || overlap.Baseline != overlap.Current || overlap.InputSHA256 == report.InputSHA256 {
		t.Fatalf("periodos superpuestos: %+v, %v", overlap, err)
	}
}

func TestHTTPComparisonRejectsInvalidCriteria(t *testing.T) {
	for _, origin := range []string{"ftp://example.invalid", "example.invalid", "https://user@example.invalid",
		"https://example.invalid/a", "https://example.invalid?", "https://example.invalid/#", "https://example.invalid:65536",
		"https://example.invalid:", "http://[not-ip]"} {
		_, err := CompareHTTP(t.Context(), nil, HTTPCompareCriteria{Baseline: HTTPWindow{Origin: origin}})
		if !errors.Is(err, ErrHTTPComparisonCriteria) {
			t.Errorf("%s: %v", origin, err)
		}
	}
	if got := normalizeHTTPOrigin("http://[2001:0DB8::01]:0080/"); got != "http://[2001:db8::1]" {
		t.Errorf("IPv6: %s", got)
	}
	a := HTTPWindow{From: "2026-11-01", To: "2026-11-01"}
	for _, invalid := range []HTTPWindow{{From: "2026-11-02", To: "2026-11-01"}, {From: "2026-02-29", To: "2026-11-01"},
		{From: a.From, To: a.To, Capture: "dns"}, {From: "0000-01-01", To: a.To}} {
		_, err := CompareHTTP(t.Context(), nil, HTTPCompareCriteria{Baseline: a, Current: invalid})
		if !errors.Is(err, ErrHTTPComparisonCriteria) || !strings.Contains(err.Error(), "periodo B") {
			t.Errorf("%+v: %v", invalid, err)
		}
	}
}

func TestHTTPComparisonCountsOverlappingLargeWindows(t *testing.T) {
	store, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	first, last := seedHTTPComparison(t, store, HTTPComparisonRecordLimit)
	window := HTTPWindow{From: first, To: last}
	criteria := HTTPCompareCriteria{Baseline: window, Current: window}
	report, err := CompareHTTP(t.Context(), store, criteria)
	if err != nil || report.Schema != HTTPComparisonWideSchema || report.Baseline.Observations != HTTPComparisonRecordLimit ||
		report.Baseline != report.Current || report.Baseline.Assessed != HTTPComparisonRecordLimit {
		t.Fatalf("periodos coincidentes: %+v, %v", report.Baseline, err)
	}
	for _, row := range report.Rows {
		if row.Baseline.Count != row.Current.Count || !reflect.DeepEqual(row.Baseline.Evidence, row.Current.Evidence) ||
			len(row.Baseline.Evidence) != referenceLimit {
			t.Fatalf("recuento y citas coincidentes: %+v", row)
		}
		for _, ref := range row.Baseline.Evidence {
			record, err := store.RecordRevision(t.Context(), ref.ID, ref.Revision)
			if err != nil || record.Title != ref.Title || record.Time != ref.Time || record.Source != ref.Origin {
				t.Fatalf("cita original: %+v, %v", ref, err)
			}
		}
	}
	if err := store.Save([]caso.Record{{Kind: "archivo HAR", Time: last + "T23:59:59Z", Title: "Captura adicional",
		Source: "https://control.invalid", Traffic: &caso.Traffic{Status: 204}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := CompareHTTP(t.Context(), store, criteria); !errors.Is(err, ErrHTTPComparisonLimit) {
		t.Fatalf("límite de observaciones únicas: %v", err)
	}
}

func TestHTTPComparisonKeepsLatestLabelsAndCitations(t *testing.T) {
	store, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	const rule = "nosniff-ausente"
	stamps := []string{
		"2026-11-01T01:00:00Z", "2026-11-01T03:00:00Z", "2026-11-01T05:00:00+02:00", "2026-11-01T04:00:00Z",
		"2026-11-01T07:00:00+03:00", "2026-11-01T06:00:00Z", "2026-11-01T06:00:00.000000001Z", "2026-11-01T05:00:00Z",
	}
	for _, stamp := range stamps {
		record := caso.Record{Kind: "archivo HAR", Time: stamp, Title: stamp, Source: "https://capture.invalid",
			Traffic: &caso.Traffic{Status: 200}, HTTPFindings: []caso.HTTPFinding{{Rule: rule, Label: stamp}}}
		if err := store.Save([]caso.Record{record}); err != nil {
			t.Fatal(err)
		}
	}
	records, err := store.Records()
	if err != nil || len(records) != len(stamps) {
		t.Fatalf("evidencia: %d capturas, %v", len(records), err)
	}
	slices.SortFunc(records, func(a, b caso.Record) int {
		first, _ := time.Parse(time.RFC3339Nano, a.Time)
		second, _ := time.Parse(time.RFC3339Nano, b.Time)
		if order := second.Compare(first); order != 0 {
			return order
		}
		return strings.Compare(a.ID, b.ID)
	})
	window := HTTPWindow{From: "2026-11-01", To: "2026-11-01"}
	report, err := CompareHTTP(t.Context(), store, HTTPCompareCriteria{Baseline: window, Current: window})
	if err != nil || len(report.Rows) != 2 {
		t.Fatalf("filas: %+v, %v", report.Rows, err)
	}
	row := report.Rows[1]
	if row.Code != rule || row.Label != records[0].Title || row.Baseline.Count != len(stamps) ||
		len(row.Baseline.Evidence) != referenceLimit || !reflect.DeepEqual(row.Baseline, row.Current) {
		t.Fatalf("regla: %+v", row)
	}
	for index, cite := range row.Baseline.Evidence {
		if cite.ID != records[index].ID || cite.HTTPRule != rule || cite.Revision != 1 {
			t.Fatalf("cita %d: %+v", index, cite)
		}
	}
}
