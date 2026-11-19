package ingesta

import (
	"strings"
	"testing"

	"pavarotti/internal/caso"
)

func TestImportRDAPDomainSearch(t *testing.T) {
	const payload = `{"domainSearchResults":[{
		"objectClassName":"domain","ldhName":"EXAMPLE.INVALID.","handle":"D1","status":["active"],
		"nameservers":[{"ldhName":"NS.EXAMPLE.INVALID."}],
		"events":[{"eventAction":"registration","eventDate":"2024-03-01T12:00:00+02:00"}],
		"entities":[{"vcardArray":["vcard",[["email",{},"text","contact@example.invalid"]]]}],
		"links":[{"href":"https://private.example.invalid/a"}]
	}]}`
	records, err := Parse("rdap", strings.NewReader(payload))
	if err != nil || len(records) != 1 {
		t.Fatalf("records=%v err=%v", records, err)
	}
	record := records[0]
	if record.Kind != "rdap" || record.SHA256 != caso.Hash([]byte(payload)) || record.SourceID != "#/domainSearchResults/0" ||
		record.Source != "example.invalid, ns.example.invalid" || !strings.Contains(record.Details, "2024-03-01T10:00:00Z") ||
		strings.Contains(record.Details, "contact@") || strings.Contains(record.Details, "https://") {
		t.Fatal(record)
	}
}

func TestImportRDAPNetwork(t *testing.T) {
	const payload = `{"objectClassName":"ip network","ipVersion":"v6","startAddress":"2001:db8::","endAddress":"2001:db8::ff","name":"DOCS","country":"ZZ"}`
	records, err := Parse("rdap", strings.NewReader(payload))
	if err != nil || len(records) != 1 {
		t.Fatalf("records=%v err=%v", records, err)
	}
	record := records[0]
	if record.Source != "" || record.SourceID != "#" || !strings.Contains(record.Title, "2001:db8:: – 2001:db8::ff") ||
		!strings.Contains(record.Details, "DOCS") {
		t.Fatal(record)
	}
}

func TestRejectInvalidRDAP(t *testing.T) {
	for _, payload := range []string{
		`{"objectClassName":"domain","ldhName":"a[.]invalid"}`,
		`{"objectClassName":"domain","ldhName":"a.invalid","events":[{"eventAction":"registration","eventDate":"2024"}]}`,
		`{"objectClassName":"entity","handle":"CONTACT"}`,
		`{"objectClassName":"ip network","ipVersion":"v4","startAddress":"192.0.2.3","endAddress":"192.0.2.2"}`,
		`{"objectClassName":"ip network","ipVersion":"v6","startAddress":"192.0.2.3","endAddress":"2001:db8::ff"}`,
		`{"domainSearchResults":[{"objectClassName":"domain","ldhName":"a.invalid"},null]}`,
	} {
		if records, err := Parse("rdap", strings.NewReader(payload)); err == nil || len(records) != 0 {
			t.Fatalf("input=%s records=%v err=%v", payload, records, err)
		}
	}
}
