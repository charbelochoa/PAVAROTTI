package caso

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"strings"
	"testing"
	"time"
)

func openAuditTest(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("PAVAROTTI_TEST_POSTGRES")
	if dsn == "" {
		t.Skip("PAVAROTTI_TEST_POSTGRES no configurado")
	}
	name := "test-actividad-" + hex.EncodeToString(randBytes(t))
	store, err := OpenPostgres(t.Context(), dsn, name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		defer store.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, query := range []string{
			"DELETE FROM pavarotti_audit_events WHERE expediente = $1",
			"DELETE FROM pavarotti_audit_heads WHERE expediente = $1",
			"DELETE FROM pavarotti_analysis_jobs WHERE expediente = $1",
			"DELETE FROM pavarotti_note_revisions WHERE expediente = $1",
			"DELETE FROM pavarotti_evidence_batches WHERE expediente = $1",
		} {
			if _, err := store.db.ExecContext(ctx, query, name); err != nil {
				t.Error(err)
			}
		}
	})
	return store
}

func TestAuditFollowsCommittedEvidenceAndRevisions(t *testing.T) {
	first, second := openAuditTest(t), openAuditTest(t)
	code := fixtureCode(t, first)
	ctx := first.AuditContext(t.Context(), SharedAccount{Name: "revisor", Role: SharedAnalyst})
	const privateText = "Texto de prueba exclusivo de la evidencia"
	note := Record{Kind: "nota", Time: Now(), Title: "Incidente", Details: privateText}
	for _, store := range []*Store{first, second} {
		if result, err := store.SaveEvidence(ctx, []Record{note}); err != nil || result.Imported != 1 {
			t.Fatalf("nota: %+v, %v", result, err)
		}
	}
	if result, err := first.SaveEvidence(ctx, []Record{note}); err != nil || result.Duplicates != 1 {
		t.Fatalf("duplicado: %+v, %v", result, err)
	}
	listed, err := first.Page(ctx, PageRequest{Kind: "nota"})
	if err != nil || len(listed.Rows) != 1 {
		t.Fatalf("página de notas: %+v, %v", listed, err)
	}
	noteID := listed.Rows[0].ID
	results := make(chan error, 6)
	for range cap(results) {
		go func() {
			_, err := first.EditContext(ctx, noteID, 1, note.Title, "", privateText)
			results <- err
		}()
	}
	committed := 0
	for range cap(results) {
		err := <-results
		if err == nil {
			committed++
		} else if !errors.Is(err, ErrRevisionConflict) {
			t.Fatal(err)
		}
	}
	if committed != 1 {
		t.Fatalf("ediciones confirmadas: %d", committed)
	}
	if _, err := first.ClassifyCode(ctx, code.ID, fixtureSignal, 0, "confirmada", privateText); err != nil {
		t.Fatal(err)
	}
	if _, err := first.ClassifyCode(ctx, code.ID, fixtureSignal, 0, "descartada", privateText); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("decisión obsoleta: %v", err)
	}
	page, err := first.AuditPage(ctx, 0, 2)
	if err != nil || len(page.Events) != 2 || page.Next != 3 {
		t.Fatalf("actividad reciente: %+v, %v", page, err)
	}
	triage, edit := page.Events[0], page.Events[1]
	if triage.Action != AuditTriage || triage.Target != code.ID || triage.Position != 4 || triage.Actor != "revisor" ||
		triage.Source != "sesion" || triage.Details.Finding == nil || *triage.Details.Finding != fixtureSignal || triage.Details.Status != "confirmada" {
		t.Fatalf("evento de triaje: %+v", triage)
	}
	if edit.Action != AuditEdit || edit.Target != noteID || edit.Details.Revision != 2 || edit.Actor != "revisor" {
		t.Fatalf("evento de edición: %+v", edit)
	}
	encoded, err := json.Marshal(page)
	if err != nil || strings.Contains(string(encoded), privateText) {
		t.Fatal("el registro de actividad incluyó contenido de la evidencia")
	}
	earlier, err := first.AuditPage(ctx, page.Next, 2)
	if err != nil || len(earlier.Events) != 2 || earlier.Next != 0 || earlier.Events[0].Action != AuditNote || earlier.Events[1].Action != AuditEvidence {
		t.Fatalf("actividad anterior: %+v, %v", earlier, err)
	}
	other, err := second.AuditPage(ctx, 0, 100)
	if err != nil || len(other.Events) != 1 || other.Events[0].Position != 1 || other.Events[0].Source != "postgres" || other.Events[0].Target != noteID {
		t.Fatalf("actividad del segundo expediente: %+v, %v", other, err)
	}
}

func TestAuditFailureRollsBackMutation(t *testing.T) {
	store := openAuditTest(t)
	ctx := t.Context()
	note := Record{Kind: "nota", Time: Now(), Title: "Primera nota", Details: "Versión original"}
	if err := store.Save([]Record{note}); err != nil {
		t.Fatal(err)
	}
	page, err := store.AuditPage(ctx, 0, 100)
	if err != nil || len(page.Events) != 1 {
		t.Fatalf("actividad inicial: %+v, %v", page, err)
	}
	id := page.Events[0].Target
	if _, err := store.db.ExecContext(ctx, `UPDATE pavarotti_audit_heads SET position = $2 WHERE expediente = $1`, store.expediente, int64(math.MaxInt64)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.EditContext(ctx, id, 1, "Edición", "", "Cambio de prueba"); err == nil {
		t.Fatal("se guardó la edición cuando falló su evento")
	}
	note.Title = "Segunda nota"
	if result, err := store.SaveEvidence(ctx, []Record{note}); err == nil || result.Imported != 0 {
		t.Fatalf("se guardó evidencia cuando falló su evento: %+v, %v", result, err)
	}
	records, err := store.Records()
	if err != nil || len(records) != 1 || records[0].Revision != 1 || records[0].Title != "Primera nota" {
		t.Fatalf("estado tras el fallo: %+v, %v", records, err)
	}
	page, err = store.AuditPage(ctx, 0, 100)
	if err != nil || len(page.Events) != 1 || page.Events[0].Position != 1 {
		t.Fatalf("actividad tras el fallo: %+v, %v", page, err)
	}
}
