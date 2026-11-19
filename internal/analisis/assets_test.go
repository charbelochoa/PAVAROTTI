package analisis

import (
	"errors"
	"strings"
	"testing"

	"pavarotti/internal/caso"
)

func TestAssetsKeepEvidenceRolesAndSampleDigests(t *testing.T) {
	const domain = "evidencia.example.invalid"
	hash := strings.Repeat("a", 64)
	store, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	for _, record := range []caso.Record{
		{Kind: "nota", Title: "Referencia manual", Source: domain, Time: "2026-02-01T02:00:00Z"},
		{Kind: "dns", Source: domain + ", " + domain + ", 192.0.2.12", SHA256: strings.Repeat("d", 64), Time: "2026-02-01T01:00:00Z"},
		{Kind: "archivo HAR", Source: "https://" + domain + ":443/ruta,oculta", Traffic: &caso.Traffic{Status: 404}},
		{Kind: "rdap", Source: domain + ", invalid", SourceID: "#"},
		{Kind: "binario", SHA256: hash},
		{Kind: "stix", SHA256: strings.Repeat("c", 64), Indicator: &caso.Indicator{Type: "sha256", Value: hash}},
		{Kind: "stix", SHA256: strings.Repeat("b", 64), Indicator: &caso.Indicator{Type: "dominio", Value: domain}},
	} {
		if err := store.Save([]caso.Record{record}); err != nil {
			t.Fatal(err)
		}
	}
	ctx := t.Context()
	first, err := ListAssets(ctx, store, AssetQuery{Limit: 2})
	if err != nil || len(first.Rows) != 2 || first.Rows[0].Value != domain || first.Rows[0].Count != 5 ||
		first.Rows[1].Value != "invalid" || first.Next == "" {
		t.Fatalf("índice: %+v, %v", first, err)
	}
	second, err := ListAssets(ctx, store, AssetQuery{Limit: 2, After: first.Next})
	if err != nil || len(second.Rows) != 2 || second.Rows[0].Value != "192.0.2.12" ||
		second.Rows[1].Value != hash || second.Rows[1].Count != 2 || second.Next != "" {
		t.Fatalf("segunda página: %+v, %v", second, err)
	}
	query := AssetQuery{AssetKey: AssetKey{Type: "dominio", Value: strings.ToUpper(domain) + "."}, Limit: 2}
	card, err := DescribeAsset(ctx, store, query)
	if err != nil || card.Count != 5 || card.Indicators != 1 || card.Value != domain || len(card.Rows) != 2 ||
		card.Rows[0].Role != "referencia" || card.Rows[1].Role != "observación" || card.Rows[1].ID != card.Next {
		t.Fatalf("ficha: %+v, %v", card, err)
	}
	query.After, query.Limit = card.Next, 5
	rest, err := DescribeAsset(ctx, store, query)
	if err != nil || len(rest.Rows) != 3 || rest.Next != "" || rest.Rows[0].Revision != 1 {
		t.Fatalf("referencias: %+v, %v", rest, err)
	}
	for _, row := range rest.Rows {
		if record, err := store.RecordRevision(ctx, row.ID, row.Revision); err != nil || record.Kind != row.Kind {
			t.Fatalf("cita rota: %+v, %v", row, err)
		}
	}
	if _, err := DescribeAsset(ctx, store, AssetQuery{AssetKey: AssetKey{Type: "sha256", Value: strings.Repeat("d", 64)}}); !errors.Is(err, caso.ErrNotFound) {
		t.Fatalf("la huella del archivo DNS se trató como huella de muestra: %v", err)
	}
	if _, err := ListAssets(ctx, store, AssetQuery{After: "ipv4/host.invalid"}); !errors.Is(err, ErrAssetQuery) {
		t.Fatalf("cursor inválido: %v", err)
	}
}

func TestAssetNetworkCoverageKeepsObservedAddressesDistinct(t *testing.T) {
	store, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save([]caso.Record{
		{Kind: "dns", Source: "192.0.2.5, 2001:db8::7"},
		{Kind: "rdap", Title: "Red · 192.0.2.2 – 192.0.2.5"},
		{Kind: "rdap", Title: "Red · 192.0.2.5 – 192.0.2.5", Source: "192.0.2.5"},
		{Kind: "stix", Network: "192.0.2.0/24"},
		{Kind: "stix", Title: "Red · 2001:db8::/32"},
		{Kind: "nota", Title: "Red · 0.0.0.0/0"},
	}); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		kind, value       string
		direct, coverages int
	}{
		{"ipv4", "192.0.2.5", 2, 2},
		{"ipv4", "192.0.2.6", 0, 1},
		{"ipv6", "2001:db8::7", 1, 1},
		{"red", "192.0.2.9/24", 1, 0},
	} {
		detail, err := DescribeAsset(t.Context(), store, AssetQuery{AssetKey: AssetKey{Type: test.kind, Value: test.value}})
		if err != nil || detail.Count != test.direct || detail.Coverage != test.coverages || len(detail.Rows) != test.direct+test.coverages {
			t.Fatalf("%s: %+v, %v", test.value, detail, err)
		}
	}
	page, err := ListAssets(t.Context(), store, AssetQuery{AssetKey: AssetKey{Type: "ipv4"}})
	if err != nil || len(page.Rows) != 1 || page.Rows[0].Value != "192.0.2.5" || page.Rows[0].Count != 2 {
		t.Fatalf("la cobertura generó observaciones: %+v, %v", page, err)
	}
	if _, err := DescribeAsset(t.Context(), store, AssetQuery{AssetKey: AssetKey{Type: "ipv4", Value: "192.0.3.6"}}); !errors.Is(err, caso.ErrNotFound) {
		t.Fatalf("dirección ajena al rango: %v", err)
	}
}

func TestAssetInventoryPaginatesLargeCases(t *testing.T) {
	for _, backend := range []string{"local", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			store := openAssetScaleStore(t, backend)
			const observations = RecordLimit + 12
			saveAssetScaleFixture(t, store, observations)
			if err := store.Save([]caso.Record{
				{Kind: "indicador", Indicator: &caso.Indicator{Type: "ipv4", Value: "198.18.0.1"}},
				{Kind: "dns", Source: "198.18.0.1, 198.18.0.100"},
			}); err != nil {
				t.Fatal(err)
			}
			domains, err := ListAssets(t.Context(), store, AssetQuery{AssetKey: AssetKey{Type: "dominio"}, Limit: 1})
			if err != nil || len(domains.Rows) != 1 || domains.Rows[0].Value != "activo.example.invalid" ||
				domains.Rows[0].Count != observations || domains.Next != "dominio/activo.example.invalid" {
				t.Fatalf("dominios: %+v, %v", domains, err)
			}
			query := AssetQuery{AssetKey: AssetKey{Type: "ipv4"}, Search: "198.18.0.", Limit: 2}
			first, err := ListAssets(t.Context(), store, query)
			if err != nil || len(first.Rows) != 2 || first.Rows[0].Value != "198.18.0.0" ||
				first.Rows[1].Value != "198.18.0.1" || first.Rows[1].Count != 3 || first.Rows[1].Indicators != 1 ||
				first.Next != "ipv4/198.18.0.1" {
				t.Fatalf("primera página: %+v, %v", first, err)
			}
			query.After = first.Next
			second, err := ListAssets(t.Context(), store, query)
			if err != nil || len(second.Rows) != 2 || second.Rows[0].Value != "198.18.0.10" ||
				second.Rows[1].Value != "198.18.0.100" || second.Rows[1].Count != 2 {
				t.Fatalf("segunda página: %+v, %v", second, err)
			}
			detailQuery := AssetQuery{AssetKey: AssetKey{Type: "dominio", Value: "activo.example.invalid"}, Limit: 1}
			firstSource, err := DescribeAsset(t.Context(), store, detailQuery)
			if err != nil || firstSource.Count != observations || len(firstSource.Rows) != 1 ||
				firstSource.Rows[0].SourceID != "paquete/respuesta/10011" || firstSource.Next == "" {
				t.Fatalf("ficha con muchas coincidencias: %+v, %v", firstSource, err)
			}
			detailQuery.After = firstSource.Next
			secondSource, err := DescribeAsset(t.Context(), store, detailQuery)
			if err != nil || secondSource.Count != observations || len(secondSource.Rows) != 1 ||
				secondSource.Rows[0].SourceID != "paquete/respuesta/10010" || secondSource.Next == "" {
				t.Fatalf("segunda página de fuentes: %+v, %v", secondSource, err)
			}
		})
	}
}

func TestAssetSourceCursorUsesUTCAndCurrentEvidence(t *testing.T) {
	for _, backend := range []string{"local", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			store := openAssetScaleStore(t, backend)
			const ip = "192.0.2.42"
			if err := store.Save([]caso.Record{
				{Kind: "stix", Title: "Prefijo STIX", Network: "192.0.2.32/27", Time: "2026-06-01T10:00:00Z"},
				{Kind: "nota", Title: "Nota intermedia", Source: ip, Time: "2026-06-01T18:00:00+05:30"},
				{Kind: "dns", Title: "Observada después", Source: ip, Time: "2026-06-01T13:00:00Z"},
				{Kind: "rdap", Title: "Rango RDAP", Network: "192.0.2.40 – 192.0.2.49", Time: "2026-06-01T11:00:00Z"},
			}); err != nil {
				t.Fatal(err)
			}
			query := AssetQuery{AssetKey: AssetKey{Type: "ipv4", Value: ip}, Limit: 2}
			detail, err := DescribeAsset(t.Context(), store, query)
			if err != nil || detail.Count != 2 || detail.Coverage != 2 || len(detail.Rows) != 2 ||
				detail.Rows[0].Kind != "dns" || detail.Rows[1].Kind != "nota" || detail.Next != detail.Rows[1].ID {
				t.Fatalf("fuentes por instante UTC: %+v, %v", detail, err)
			}
			query.After = detail.Next
			rest, err := DescribeAsset(t.Context(), store, query)
			if err != nil || len(rest.Rows) != 2 || rest.Rows[0].Kind != "rdap" || rest.Rows[1].Kind != "stix" ||
				rest.Rows[0].Role != "cobertura" || rest.Rows[1].Role != "cobertura" || rest.Next != "" {
				t.Fatalf("cobertura tras el cursor: %+v, %v", rest, err)
			}
			for _, cited := range rest.Rows {
				original, err := store.RecordRevision(t.Context(), cited.ID, cited.Revision)
				if err != nil || original.Network != cited.Network {
					t.Fatalf("cita: %+v, %v", original, err)
				}
			}
			if _, err := store.EditContext(t.Context(), query.After, 1, "Nota revisada", "192.0.2.58", "Cambio de referencia"); err != nil {
				t.Fatal(err)
			}
			if _, err := DescribeAsset(t.Context(), store, query); !errors.Is(err, ErrAssetQuery) {
				t.Fatalf("cursor que dejó de pertenecer al activo: %v", err)
			}
			query.After = rest.Rows[1].ID
			last, err := DescribeAsset(t.Context(), store, query)
			if err != nil || last.Count != 1 || last.Coverage != 2 || last.Rows == nil || len(last.Rows) != 0 || last.Next != "" {
				t.Fatalf("después de la última cita: %+v, %v", last, err)
			}
		})
	}
}
