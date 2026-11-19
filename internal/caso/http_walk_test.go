package caso

import (
	"reflect"
	"testing"
)

func TestPostgresHTTPWalkPreservesEvidenceOrdinals(t *testing.T) {
	store, other := openAuditTest(t), openAuditTest(t)
	record := Record{Kind: "archivo HAR", Time: Now(), Title: "GET 204", Source: "https://lab.invalid",
		Traffic: &Traffic{Method: "GET", Status: 204}, HTTPRuleSet: 1}
	if err := store.Save([]Record{{Kind: "nota", Time: Now(), Title: "Nota"}, record}); err != nil {
		t.Fatal(err)
	}
	if err := other.Save([]Record{record}); err != nil {
		t.Fatal(err)
	}
	var results []Record
	if err := store.WalkHTTP(t.Context(), func(item Record) error {
		results = append(results, item)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("evidencia del expediente: %+v", results)
	}
	got := results[0]
	_, ordinal, valid := recordPosition(got.ID)
	saved, err := store.RecordRevision(t.Context(), got.ID, got.Revision)
	if err != nil || !valid || ordinal != 2 || got.Revision != 1 || got.HTTPRuleSet != 1 || !reflect.DeepEqual(got, saved) {
		t.Fatalf("cita de la observación: %+v, %v", got, err)
	}
}
