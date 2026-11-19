package analisis

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"pavarotti/internal/caso"
)

func TestSavedSnapshotCorrelatesSampleDigestsAndObservedNetworks(t *testing.T) {
	ctx := t.Context()
	store, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sha := strings.Repeat("a", 64)
	artifact := strings.Repeat("b", 64)
	if err := store.Save([]caso.Record{
		{Kind: "binario", Title: "Muestra", SHA256: sha},
		{Kind: "indicador", Indicator: &caso.Indicator{Type: "sha256", Value: sha}},
		{Kind: "indicador", Indicator: &caso.Indicator{Type: "sha256", Value: artifact}},
		{Kind: "dns", Source: "a.invalid, 192.0.2.1, 192.0.2.7", SHA256: artifact},
		{Kind: "dns", Source: "192.0.2.7, 192.0.3.1, 2001:db8::1"},
		{Kind: "archivo HAR", Source: "http://[2001:db8::9]:81/private", Traffic: &caso.Traffic{Status: 200}},
		{Kind: "nota", Title: "Referencia", Source: "192.0.2.200"},
		{Kind: "rdap", Title: "Red · 192.0.2.1 – 192.0.2.7"},
		{Kind: "stix", Network: "2001:db8::/32"},
		{Kind: "stix", Network: "192.0.2.0/24"},
		{Kind: "rdap", Title: "Red · 198.51.100.1 – 198.51.100.255"},
	}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := Prepare(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	encoded, failure := claimResult(ctx, caso.AnalysisClaim{Snapshot: payload,
		Job: caso.AnalysisJob{AgentVersion: AgentVersion, Fingerprint: snapshot.Fingerprint}})
	var report Report
	if failure != "" || json.Unmarshal(encoded, &report) != nil || report.AgentVersion != AgentVersion || report.InputSHA256 != snapshot.Fingerprint {
		t.Fatalf("resultado guardado: %s · %s", encoded, failure)
	}
	if len(report.HashMatches) != 1 || report.HashMatches[0].Value != sha || report.HashMatches[0].Count != 1 ||
		report.HashMatches[0].Evidence[0].Kind != "indicador" || report.HashMatches[0].Evidence[1].Kind != "binario" {
		t.Fatalf("huellas: %+v", report.HashMatches)
	}
	if len(report.NetworkMatches) != 3 {
		t.Fatalf("redes: %+v", report.NetworkMatches)
	}
	for _, group := range report.NetworkMatches {
		expected := []string{"192.0.2.1", "192.0.2.7"}
		if strings.HasPrefix(group.Value, "2001:") {
			expected = []string{"2001:db8::1", "2001:db8::9"}
		}
		if group.Count != 2 || !slices.Equal(group.Samples, expected) || len(group.Evidence) < 2 {
			t.Fatalf("cobertura: %+v", group)
		}
		for _, entry := range group.Evidence {
			if record, err := store.RecordRevision(ctx, entry.ID, entry.Revision); err != nil || record.Kind != entry.Kind {
				t.Fatalf("procedencia: %+v, %v", entry, err)
			}
		}
	}
	legacy := snapshot
	legacy.AgentVersion = legacyAgent
	legacy.Records = slices.Clone(snapshot.Records)
	for index := range legacy.Records {
		legacy.Records[index].Network = ""
	}
	legacy.Fingerprint, err = legacy.checksum(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload, err = json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	encoded, failure = claimResult(ctx, caso.AnalysisClaim{Snapshot: payload,
		Job: caso.AnalysisJob{AgentVersion: legacyAgent, Fingerprint: legacy.Fingerprint}})
	var previous Report
	if failure != "" || json.Unmarshal(encoded, &previous) != nil || previous.AgentVersion != legacyAgent ||
		previous.InputSHA256 != legacy.Fingerprint || len(previous.Agents) != 3 || len(previous.HashMatches)+len(previous.NetworkMatches) != 0 {
		t.Fatalf("compatibilidad: %s · %s", encoded, failure)
	}
}
