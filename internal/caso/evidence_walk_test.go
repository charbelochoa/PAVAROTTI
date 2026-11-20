package caso

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestLocalEvidencePeriodsUseRecordedInstants(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	testEvidencePeriods(t, store)
}

func TestPostgresEvidencePeriodsUseRecordedInstants(t *testing.T) {
	testEvidencePeriods(t, openAuditTest(t))
}

func TestHTTPWindowReadsPendingAndLegacyBatches(t *testing.T) {
	store := openAuditTest(t)
	ctx := t.Context()
	times := map[string]string{
		"En el índice": "2026-11-05T00:00:00Z",
		"Con desfase":  "2026-11-06T00:10:00+02:00",
		"Por indexar":  "2026-11-05T12:00:00Z",
		"Otro día":     "2026-11-10T00:00:00Z",
	}
	for title, stamp := range times {
		record := Record{Kind: "archivo HAR", Title: title, Time: stamp, Traffic: &Traffic{Status: 200}}
		if err := store.Save([]Record{record}); err != nil {
			t.Fatal(err)
		}
	}
	records, err := store.Records()
	if err != nil || len(records) != len(times) {
		t.Fatalf("lotes: %d, %v", len(records), err)
	}
	for _, record := range records {
		if record.Title == "Por indexar" {
			batch, _, _ := recordPosition(record.ID)
			if _, err := store.db.ExecContext(ctx, "DELETE FROM pavarotti_http_page WHERE expediente=$1 AND batch_key=$2", store.expediente, batch); err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.ExecContext(ctx, "UPDATE pavarotti_evidence_batches SET http_page_indexed=false WHERE expediente=$1 AND batch_key=$2", store.expediente, batch); err != nil {
				t.Fatal(err)
			}
		}
	}
	start := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	filter := EvidenceFilter{HTTP: true, Periods: []EvidencePeriod{{Start: start, End: start.AddDate(0, 0, 1)}}}
	for _, name := range []string{"acotada", "amplia"} {
		t.Run(name, func(t *testing.T) {
			windows := filter
			if name == "amplia" {
				windows.Periods = append(windows.Periods, EvidencePeriod{Start: start.AddDate(0, 0, -14), End: start.AddDate(0, 0, -7)})
			}
			var titles []string
			if err := store.WalkFiltered(t.Context(), windows, func(record Record) error {
				titles = append(titles, record.Title)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			slices.Sort(titles)
			if !slices.Equal(titles, []string{"Con desfase", "En el índice", "Por indexar"}) {
				t.Fatalf("ventana: %v", titles)
			}
		})
	}
}

func testEvidencePeriods(t *testing.T, store *Store) {
	t.Helper()
	traffic := &Traffic{Status: 204}
	records := []Record{
		{Kind: "archivo HAR", Title: "Último nanosegundo", Time: "2026-11-06T23:59:59.999999999Z", Traffic: traffic},
		{Kind: "archivo HAR", Title: "Fecha con desfase", Time: "2026-11-07T01:00:00+02:00", Traffic: traffic},
		{Kind: "archivo HAR", Title: "Fuera de la ventana", Time: "2026-11-07T00:00:00Z", Traffic: traffic},
		{Kind: "archivo HAR", Title: "Segunda ventana", Time: "2026-11-09T00:00:00Z", Traffic: traffic},
		{Kind: "archivo HAR", Title: "Marca inválida", Time: "2026-11-09TincorrectaZ", Traffic: traffic},
		{Kind: "nota", Title: "Nota inicial", Time: "2026-11-06T01:00:00Z", Details: "Texto inicial"},
	}
	if err := store.Save(records); err != nil {
		t.Fatal(err)
	}
	initial, err := store.Records()
	if err != nil || len(initial) != len(records) {
		t.Fatalf("registros originales: %+v, %v", initial, err)
	}
	note := initial[5]
	if _, err = store.EditContext(t.Context(), note.ID, note.Revision, "Nota revisada", "", "Texto vigente"); err != nil {
		t.Fatal(err)
	}
	day := func(day int) EvidencePeriod {
		start := time.Date(2026, 11, day, 0, 0, 0, 0, time.UTC)
		return EvidencePeriod{Start: start, End: start.AddDate(0, 0, 1)}
	}
	filter := EvidenceFilter{HTTP: true, Periods: []EvidencePeriod{day(6), day(9), day(9)}}
	var names []string
	if err := store.WalkFiltered(t.Context(), filter, func(record Record) error {
		found := slices.ContainsFunc(initial, func(original Record) bool {
			return original.ID == record.ID && original.Time == record.Time && original.Title == record.Title
		})
		if !found || record.Revision != 1 {
			t.Errorf("cita de tráfico inesperada: %+v", record)
		}
		names = append(names, record.Title)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"Fecha con desfase", "Segunda ventana", "Último nanosegundo"}) {
		t.Fatalf("ventanas: %v", names)
	}
	names = nil
	filter.HTTP = false
	if err := store.WalkFiltered(t.Context(), filter, func(record Record) error {
		if record.Kind == "nota" && (record.Revision != 2 || record.ID != note.ID || record.Time != note.Time) {
			t.Errorf("nota vigente: %+v", record)
		}
		names = append(names, record.Title)
		return nil
	}); err != nil || len(names) != 4 || !slices.Contains(names, "Nota revisada") {
		t.Fatalf("fuentes y revisiones: %v, %v", names, err)
	}
}

func TestLocalDateBoundsRefreshAfterBatchChanges(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first := Record{Kind: "archivo HAR", Title: "Muestra", Time: "2026-11-06T00:00:00Z", Traffic: &Traffic{Status: 204}}
	if err := store.Save([]Record{first}); err != nil {
		t.Fatal(err)
	}
	inventory, err := store.Records()
	if err != nil || len(inventory) != 1 {
		t.Fatalf("lote original: %v, %v", inventory, err)
	}
	key, _, _ := recordPosition(inventory[0].ID)
	day := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	filter := EvidenceFilter{HTTP: true, Periods: []EvidencePeriod{{Start: day, End: day.AddDate(0, 0, 1)}}}
	count := func() int {
		t.Helper()
		hits := 0
		if err := store.WalkFiltered(t.Context(), filter, func(Record) error { hits++; return nil }); err != nil {
			t.Fatal(err)
		}
		return hits
	}
	if count() != 0 || count() != 0 {
		t.Fatal("el lote de otro día apareció en el filtro")
	}
	path := filepath.Join(store.path, key+".json")
	first.Time = day.Format(time.RFC3339Nano)
	data, err := json.Marshal([]Record{first})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, day, day); err != nil {
		t.Fatal(err)
	}
	if count() != 1 {
		t.Fatal("el filtro reutilizó el intervalo anterior")
	}
}
