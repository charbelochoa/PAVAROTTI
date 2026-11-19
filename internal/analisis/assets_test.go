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
