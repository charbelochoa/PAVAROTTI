package analisis

import (
	"errors"
	"reflect"
	"testing"

	"pavarotti/internal/caso"
)

func TestAssetCoverageUsesRecordedDaysAndKeepsOriginalCitations(t *testing.T) {
	store, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	records := []caso.Record{
		{Kind: "rdap", Network: "192.0.2.2 – 192.0.2.10", Title: "Rango RDAP", Time: "2026-11-07T03:00:00Z"},
		{Kind: "stix", Network: "192.0.2.0/24", Title: "Prefijo STIX", Time: "2026-11-06T18:00:00-06:00"},
		{Kind: "dns", Source: "host.invalid, 192.0.2.2", Title: "A host.invalid", SourceID: "1/respuesta/2", Time: "2026-11-07T23:59:59.999999999Z"},
		{Kind: "dns", Source: "outside.invalid, 192.0.2.3", Title: "A outside.invalid", SourceID: "1/respuesta/3", Time: "2026-11-08T00:00:00Z"},
		{Kind: "indicador", Indicator: &caso.Indicator{Type: "ipv4", Value: "192.0.2.2"}, Time: "2026-11-07T12:00:00Z"},
		{Kind: "nota", Title: "Nota anterior", Source: "192.0.2.2", Time: "2026-11-07T12:00:00Z"},
	}
	if err := store.Save(records); err != nil {
		t.Fatal(err)
	}
	input := AssetCoverageCriteria{AssetKey: AssetKey{Type: "red", Value: "192.0.2.14/24"}, From: "2026-11-07", To: "2026-11-07"}
	network, err := CoverAsset(t.Context(), store, input)
	if err != nil || network.Schema != AssetCoverageSchema || network.Criteria.Value != "192.0.2.0/24" ||
		network.Direct != 1 || network.Addresses != 1 || network.Observations != 1 || network.Coverage != 0 ||
		len(network.Members) != 1 || network.Members[0].Value != "192.0.2.2" || len(network.InputSHA256) != 64 {
		t.Fatalf("informe de red: %+v, %v", network, err)
	}
	input.AssetKey = network.Criteria.AssetKey
	repeat, err := CoverAsset(t.Context(), store, input)
	if err != nil || !reflect.DeepEqual(network, repeat) {
		t.Fatalf("informe determinista: %+v, %v", repeat, err)
	}
	input.AssetKey = AssetKey{Type: "ipv4", Value: "192.0.2.2"}
	ip, err := CoverAsset(t.Context(), store, input)
	if err != nil || ip.Direct != 3 || ip.Indicators != 1 || ip.Coverage != 2 || len(ip.Sources) != 5 {
		t.Fatalf("informe de IP: %+v, %v", ip, err)
	}
	var note AssetReference
	for _, ref := range ip.Sources {
		if ref.Kind == "nota" {
			note = ref
		}
	}
	if _, err := store.EditContext(t.Context(), note.ID, note.Revision, "Nota revisada", "192.0.2.2", "Texto actualizado"); err != nil {
		t.Fatal(err)
	}
	cited, err := store.RecordRevision(t.Context(), note.ID, note.Revision)
	if err != nil || cited.Title != "Nota anterior" || cited.Revision != 1 {
		t.Fatalf("revisión original: %+v, %v", cited, err)
	}
	updated, err := CoverAsset(t.Context(), store, input)
	if err != nil || updated.InputSHA256 == ip.InputSHA256 || updated.Direct != ip.Direct {
		t.Fatalf("nueva huella: %+v, %v", updated, err)
	}
	input.From = "2026-11-09"
	if _, err := CoverAsset(t.Context(), store, input); !errors.Is(err, ErrAssetQuery) {
		t.Fatalf("fechas inválidas: %v", err)
	}
}

func TestAssetCoverageLimitsMatchingEvidenceInLargeCases(t *testing.T) {
	store, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	records := make([]caso.Record, RecordLimit+1)
	for index := range records {
		records[index] = caso.Record{Kind: "nota", Title: "Referencia anterior", Source: "host.invalid", Time: "2026-11-06T01:00:00Z"}
	}
	records[len(records)-1].Time = "2026-11-07T00:00:00Z"
	if err := store.Save(records); err != nil {
		t.Fatal(err)
	}
	criteria := AssetCoverageCriteria{AssetKey: AssetKey{Type: "dominio", Value: "host.invalid"}, From: "2026-11-07", To: "2026-11-07"}
	report, err := CoverAsset(t.Context(), store, criteria)
	if err != nil || report.Direct != 1 || len(report.Sources) != 1 {
		t.Fatalf("informe acotado: %+v, %v", report, err)
	}
	criteria.From = "2026-11-06"
	if _, err := CoverAsset(t.Context(), store, criteria); !errors.Is(err, ErrLimit) {
		t.Fatalf("exceso de evidencia dentro del periodo: %v", err)
	}
}
