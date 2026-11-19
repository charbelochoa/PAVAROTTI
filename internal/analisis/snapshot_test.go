package analisis

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"pavarotti/internal/caso"
)

func TestSnapshotFingerprintAndRevision(t *testing.T) {
	store, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save([]caso.Record{{Kind: "nota", Time: caso.Now(), Title: "Registro",
		Source: "https://example.invalid/private-path?token=discard-this", Details: "discard-this"}}); err != nil {
		t.Fatal(err)
	}
	first, err := Prepare(t.Context(), store)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := Prepare(t.Context(), store)
	if err != nil || first.Fingerprint != repeated.Fingerprint || len(first.Fingerprint) != 64 {
		t.Fatalf("huella inestable: %s != %s, %v", first.Fingerprint, repeated.Fingerprint, err)
	}
	payload, err := json.Marshal(first)
	if err != nil || strings.Contains(string(payload), "discard-this") || strings.Contains(string(payload), "private-path") {
		t.Fatalf("la instantánea contiene datos ajenos al análisis: %s, %v", payload, err)
	}
	if _, err := store.Edit(first.Records[0].ID, 1, "Registro", "https://example.invalid", "otro texto"); err != nil {
		t.Fatal(err)
	}
	current, err := Prepare(t.Context(), store)
	if err != nil || first.Fingerprint == current.Fingerprint || current.Records[0].Revision != 2 {
		t.Fatalf("la revisión no quedó representada: %+v, %v", current, err)
	}
	report, err := current.Analyze(t.Context())
	if err != nil || report.InputSHA256 != current.Fingerprint || len(report.Assets) != 1 ||
		report.Assets[0].Value != "example.invalid" || report.Assets[0].Evidence[0].Revision != 2 ||
		report.AgentVersion != AgentVersion {
		t.Fatalf("informe con procedencia: %+v, %v", report, err)
	}
}

func TestSnapshotStopsAboveLimit(t *testing.T) {
	store, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	records := slices.Repeat([]caso.Record{{Kind: "indicador", Title: "Prueba", Time: caso.Now()}}, RecordLimit+5)
	if err := store.Save(records); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(t.Context(), store); !errors.Is(err, ErrLimit) {
		t.Fatalf("expediente fuera del límite: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Prepare(ctx, store); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelación: %v", err)
	}
}
