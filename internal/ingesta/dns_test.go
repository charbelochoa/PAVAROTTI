package ingesta

import (
	"strings"
	"testing"

	"pavarotti/internal/caso"
)

func TestParseDNSResponseAndNegativeAnswer(t *testing.T) {
	const data = `[
		{"Status":0,"Question":[{"name":"WWW.Example.INVALID.","type":1}],"Answer":[
			{"name":"WWW.Example.INVALID.","type":5,"data":"Origin.Example.INVALID.","TTL":60},
			{"name":"origin.example.invalid.","type":1,"data":"192.0.2.25","TTL":0},
			{"name":"ORIGIN.example.invalid.","type":1,"data":"192.0.2.25","TTL":0},
			{"name":"example.invalid.","type":15,"data":"10 MAIL.example.invalid.","TTL":300},
			{"name":"_dmarc.example.invalid.","type":16,"data":"\"v=DMARC1; p=reject\"","TTL":300}
		]},
		{"Status":3,"Question":[{"name":"absent.example.invalid.","type":28}]}
	]`
	records, err := Parse("dns", strings.NewReader(data))
	if err != nil || len(records) != 5 {
		t.Fatalf("importación DNS: %d registros, %v", len(records), err)
	}
	wantHash := caso.Hash([]byte(data))
	for _, record := range records {
		if record.Kind != "dns" || record.SHA256 != wantHash || record.SourceID == "" {
			t.Fatalf("procedencia incompleta: %+v", record)
		}
	}
	if records[0].Title != "CNAME www.example.invalid" || records[0].Source != "www.example.invalid, origin.example.invalid" ||
		!strings.Contains(records[0].Details, "TTL · 60 s") || !strings.Contains(records[1].Details, "TTL · 0 s") {
		t.Fatalf("normalización o TTL: %+v, %+v", records[0], records[1])
	}
	if records[2].Source != "example.invalid, mail.example.invalid" || !strings.Contains(records[2].Details, "10 mail.example.invalid") {
		t.Fatalf("registro MX: %+v", records[2])
	}
	if records[3].Source != "_dmarc.example.invalid" || strings.Contains(records[3].Title, "DMARC1") {
		t.Fatalf("registro TXT: %+v", records[3])
	}
	if records[4].Title != "DNS AAAA absent.example.invalid" || !strings.Contains(records[4].Details, "NXDOMAIN") {
		t.Fatalf("respuesta negativa: %+v", records[4])
	}
}

func TestParseDNSRejectsMalformedArtifact(t *testing.T) {
	for _, data := range []string{
		`{}`, `[]`,
		`{"Status":0,"Answer":[{"name":"a.example","type":1,"data":"::1"}]}`,
		`{"Status":0,"Answer":[{"name":"b.example","type":33,"data":"0 10 90000 a.example"}]}`,
		`{"Status":0,"Answer":[{"name":"b.example","type":5,"data":"https://a.example"}]}`,
	} {
		if records, err := Parse("dns", strings.NewReader(data)); err == nil || len(records) != 0 {
			t.Fatalf("captura inválida aceptada: %s, %v", data, err)
		}
	}
}
