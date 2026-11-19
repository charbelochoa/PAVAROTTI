package ingesta

import (
	"fmt"
	"strings"
	"testing"

	"pavarotti/internal/analisis"
	"pavarotti/internal/caso"
)

func stixBundle(objects string) string {
	return `{"type":"bundle","id":"bundle--b451dd1c-4321-4bee-99b7-7dcaf8148f8f","objects":[` + objects + `]}`
}

func TestSTIXCorrelatesIndicatorAndDNS(t *testing.T) {
	const indicatorID = "indicator--9324a333-6a0b-4df1-8fdb-d266df2800ea"
	const domainID = "domain-name--3c34246b-46a3-5daf-82e8-002ea3559f71"
	const payloadObjects = `
	{"type":"indicator","spec_version":"2.1","id":"` + indicatorID + `",
	"pattern_type":"stix","pattern_version":"2.1","pattern":"[domain-name:value = 'a.example.invalid']"},
	{"type":"domain-name","id":"` + domainID + `","value":"B.EXAMPLE.INVALID."},
	{"type":"observed-data","spec_version":"2.1","id":"observed-data--948c79d4-99a2-4263-8a1a-a7eb72c793c1",
	"first_observed":"2024-01-01T01:00:00Z","last_observed":"2024-01-01T03:00:00+01:00","number_observed":2,
	"object_refs":["` + domainID + `"]},
	{"type":"relationship","spec_version":"2.1","id":"relationship--eb544802-ddce-42ad-9405-1d6f8dae23e7",
	"relationship_type":"related-to","source_ref":"` + indicatorID + `","target_ref":"` + domainID + `"}`
	payload := stixBundle(payloadObjects)
	records, err := Parse("stix", strings.NewReader(payload))
	if err != nil || len(records) != 4 {
		t.Fatalf("records=%v err=%v", records, err)
	}
	for index, record := range records {
		if record.SHA256 != caso.Hash([]byte(payload)) || record.SourceID != fmt.Sprintf("#/objects/%d", index) {
			t.Fatal(record)
		}
	}
	if records[0].Indicator == nil || records[0].Source != "" || records[1].Source != "b.example.invalid" ||
		records[2].Time != "2024-01-01T02:00:00Z" || !strings.Contains(records[3].Details, domainID) {
		t.Fatal(records)
	}
	store, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := store.Save(records); err != nil {
			t.Fatal(err)
		}
	}
	dns, err := Parse("dns", strings.NewReader(`{"Status":0,"Answer":[{"name":"a.example.invalid","type":1,"data":"192.0.2.10"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(dns); err != nil {
		t.Fatal(err)
	}
	snapshot, err := analisis.Prepare(t.Context(), store)
	if err != nil {
		t.Fatal(err)
	}
	report, err := snapshot.Analyze(t.Context())
	if err != nil || report.Records != 5 || len(report.Matches) != 1 || report.Matches[0].Value != "a.example.invalid" {
		t.Fatalf("report=%v error=%v", report, err)
	}
	refs := report.Matches[0].Evidence
	if len(refs) != 2 || refs[0].Kind != "stix" || refs[0].Revision != 1 || refs[0].ID == "" || refs[1].Kind != "dns" {
		t.Fatal(refs)
	}
}

func TestSTIXRecognizesLiteralHashesAndLeavesExpressionsUninterpreted(t *testing.T) {
	for _, test := range []struct{ pattern, kind string }{
		{`[file:hashes.'SHA-256' = '` + strings.Repeat("A", 64) + `']`, "sha256"},
		{`[ipv6-addr:value = '2001:db8::1']`, "ipv6"},
		{`[domain-name:value = 'one.example.invalid' OR domain-name:value = 'two.example.invalid']`, ""},
		{`[ipv4-addr:value = '2001:db8::1']`, ""},
	} {
		object := stixObject{Pattern: test.pattern, PatternType: "stix", PatternVersion: "2.1"}
		item, valid := object.indicator()
		if valid != (test.kind != "") || item.Type != test.kind {
			t.Fatalf("pattern=%s item=%v valid=%t", test.pattern, item, valid)
		}
	}
}

func TestSTIXNetworkAndValidation(t *testing.T) {
	const id = "ipv4-addr--115280b5-64c0-5b55-aa96-d23276647c09"
	records, err := Parse("stix", strings.NewReader(stixBundle(`{"type":"ipv4-addr","id":"`+id+`","value":"192.0.2.0/24"}`)))
	if err != nil || len(records) != 1 || records[0].Title != "Red · 192.0.2.0/24" || records[0].Source != "" {
		t.Fatalf("records=%v err=%v", records, err)
	}
	for _, objects := range []string{
		`null`,
		`{"type":"ipv4-addr","id":"` + id + `","value":"2001:db8::1"}`,
		`{"type":"ipv6-addr","id":"` + id + `","value":"2001:db8::1"}`,
		`{"type":"ipv4-addr","id":"` + id + `","spec_version":"2.0","value":"192.0.2.1"}`,
	} {
		if records, err := Parse("stix", strings.NewReader(stixBundle(objects))); err == nil || len(records) != 0 {
			t.Fatalf("input=%s records=%v err=%v", objects, records, err)
		}
	}
}
