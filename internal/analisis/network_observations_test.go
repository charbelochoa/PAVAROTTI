package analisis

import (
	"errors"
	"testing"

	"pavarotti/internal/caso"
)

func TestNetworkObservationsDistinguishAddressesFromDeclarations(t *testing.T) {
	store, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	fixture := []caso.Record{
		{Kind: "dns", Title: "A servicio.invalid", Source: "servicio.invalid, 192.0.2.2", SourceID: "1/respuesta/1", Time: "2026-11-02T01:00:00Z"},
		{Kind: "archivo HAR", Title: "GET 502", Source: "https://192.0.2.2", Time: "2026-11-02T02:00:00Z", Traffic: &caso.Traffic{Status: 502}},
		{Kind: "dns", Title: "AAAA otro.invalid", Source: "otro.invalid, ::ffff:192.0.2.10", SourceID: "1/respuesta/2", Time: "2026-11-02T02:00:00Z"},
		{Kind: "dns", Title: "AAAA servicio.invalid", Source: "servicio.invalid, 2001:db8::7", SourceID: "1/respuesta/3"},
		{Kind: "dns", Title: "DNS A 192.0.2.11", Source: "192.0.2.11", SourceID: "2/pregunta/1"},
		{Kind: "dns", Title: "CNAME 192.0.2.13", Source: "192.0.2.13, otro.invalid", SourceID: "3/respuesta/1"},
		{Kind: "tráfico", Source: "http://192.0.2.20", Traffic: &caso.Traffic{Status: 502}, Signals: []string{caso.ProxyNoResponseSignal}},
		{Kind: "rdap", Source: "192.0.2.21", Network: "192.0.2.21 – 192.0.2.21"},
		{Kind: "stix", Source: "192.0.2.22", Network: "192.0.2.0/24"},
		{Kind: "indicador", Indicator: &caso.Indicator{Type: "ipv4", Value: "192.0.2.23"}},
		{Kind: "archivo HAR", Source: "https://dominio.invalid", Traffic: &caso.Traffic{Status: 200}},
	}
	if err := store.Save(fixture); err != nil {
		t.Fatal(err)
	}
	first, err := ListNetworkObservations(t.Context(), store, "192.0.2.17/24", "", 1)
	if err != nil || first.Network != "192.0.2.0/24" || first.Addresses != 2 || first.Records != 3 ||
		len(first.Rows) != 1 || first.Rows[0].Value != "192.0.2.2" || first.Rows[0].Count != 2 || first.Next != "192.0.2.2" {
		t.Fatalf("primera página: %+v, %v", first, err)
	}
	for _, ref := range first.Rows[0].Evidence {
		record, err := store.RecordRevision(t.Context(), ref.ID, ref.Revision)
		if err != nil || record.Kind != ref.Kind || record.Time != ref.Time {
			t.Fatalf("cita: %+v, %v", ref, err)
		}
	}
	if first.Rows[0].Evidence[0].Kind != "archivo HAR" {
		t.Fatalf("orden de citas: %+v", first.Rows[0].Evidence)
	}
	next, err := ListNetworkObservations(t.Context(), store, first.Network, first.Next, 1)
	if err != nil || len(next.Rows) != 1 || next.Rows[0].Value != "192.0.2.10" || next.Next != "" {
		t.Fatalf("página siguiente: %+v, %v", next, err)
	}
	ranged, err := ListNetworkObservations(t.Context(), store, "192.0.2.2 – 192.0.2.10", "", 50)
	if err != nil || ranged.Addresses != 2 || ranged.Records != 3 {
		t.Fatalf("rango inclusivo: %+v, %v", ranged, err)
	}
	v6, err := ListNetworkObservations(t.Context(), store, "2001:db8::/32", "", 50)
	if err != nil || len(v6.Rows) != 1 || v6.Rows[0].Value != "2001:db8::7" {
		t.Fatalf("IPv6: %+v, %v", v6, err)
	}
	if _, err := ListNetworkObservations(t.Context(), nil, first.Network, "192.0.3.2", 1); !errors.Is(err, ErrAssetQuery) {
		t.Fatalf("cursor ajeno: %v", err)
	}
}
