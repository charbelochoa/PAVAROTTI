package caso

import "testing"

func TestBinaryListingKeepsPreviousInspectionCitations(t *testing.T) {
	verify := func(t *testing.T, store *Store) {
		t.Helper()
		ctx := t.Context()
		legacy := Record{Kind: "binario", Title: "ELF", Time: Now(), SHA256: Hash([]byte("muestra")), Details: `{"format":"ELF"}`}
		if result, err := store.SaveEvidence(ctx, []Record{legacy}); err != nil || result.Imported != 1 {
			t.Fatalf("análisis anterior: %+v, %v", result, err)
		}
		legacyID := Hash([]byte("binario:"+legacy.SHA256)) + "-1"
		updated := legacy
		updated.BinaryListing = 1
		updated.Details = `{"format":"ELF","instructions":[{"address":"0x1000"}]}`
		if result, err := store.SaveEvidence(ctx, []Record{updated}); err != nil || result.Imported != 1 {
			t.Fatalf("análisis nuevo: %+v, %v", result, err)
		}
		if result, err := store.SaveEvidence(ctx, []Record{updated}); err != nil || result.Duplicates != 1 {
			t.Fatalf("repetición del análisis nuevo: %+v, %v", result, err)
		}
		if page, err := store.Page(ctx, PageRequest{Kind: "binario"}); err != nil || len(page.Rows) != 2 {
			t.Fatalf("análisis en el expediente: %+v, %v", page, err)
		}
		if previous, err := store.RecordRevision(ctx, legacyID, 1); err != nil || previous.Details != legacy.Details || previous.SHA256 != legacy.SHA256 {
			t.Fatalf("análisis anterior por su referencia: %+v, %v", previous, err)
		}
	}
	t.Run("local", func(t *testing.T) {
		store, err := Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		verify(t, store)
	})
	t.Run("PostgreSQL", func(t *testing.T) {
		verify(t, openAuditTest(t))
	})
}
