package analisis

import (
	"strings"
	"testing"

	"pavarotti/internal/caso"
)

func TestSTIXLinksPreserveMissingTargetsAndPackageProvenance(t *testing.T) {
	const domain = "domain-name--3c34246b-46a3-5daf-82e8-002ea3559f71"
	const missing = "ipv4-addr--115280b5-64c0-5b55-aa96-d23276647c09"
	const relationship = "relationship--eb544802-ddce-42ad-9405-1d6f8dae23e7"
	const observed = "observed-data--948c79d4-99a2-4263-8a1a-a7eb72c793c1"
	first, second := strings.Repeat("e", 64), strings.Repeat("b", 64)
	store, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, records := range [][]caso.Record{
		{
			{Kind: "stix", SHA256: first, SourceID: "#/objects/0", Details: "Objeto STIX · " + relationship + "\nOrigen · " + domain + "\nDestino · " + missing},
			{Kind: "stix", SHA256: first, SourceID: "#/objects/1", Details: "Objeto STIX · " + domain},
		},
		{
			{Kind: "stix", SHA256: second, SourceID: "#/objects/0", STIX: &caso.STIXObject{ID: domain}},
			{Kind: "stix", SHA256: second, SourceID: "#/objects/1", STIX: &caso.STIXObject{ID: observed,
				Refs: []caso.STIXRef{{Role: "observado", ID: domain}}}},
		},
	} {
		if err := store.Save(records); err != nil {
			t.Fatal(err)
		}
	}
	records, err := store.Records()
	if err != nil {
		t.Fatal(err)
	}
	var root string
	for _, record := range records {
		if record.STIXObject().ID == relationship {
			root = record.ID
		}
	}
	page, err := RelatedSTIX(t.Context(), store, root, 0)
	if err != nil || len(page.Rows) != 3 || page.Rows[0].Evidence.SHA256 != first || !page.Rows[0].SamePackage ||
		page.Rows[1].Evidence.SHA256 != second || page.Rows[1].SamePackage || page.Rows[2].Evidence != nil || page.Rows[2].ID != missing {
		t.Fatalf("relación: %+v, %v", page, err)
	}
	page, err = RelatedSTIX(t.Context(), store, page.Rows[0].Evidence.ID, 0)
	if err != nil || len(page.Rows) != 2 || !page.Rows[0].Incoming || page.Rows[0].ID != relationship ||
		page.Rows[0].Evidence.Revision != 1 || page.Rows[1].ID != observed || page.Rows[1].Role != "observado" {
		t.Fatalf("relaciones entrantes: %+v, %v", page, err)
	}
}
