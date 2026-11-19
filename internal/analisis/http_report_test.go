package analisis

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"pavarotti/internal/caso"
	"pavarotti/internal/trafico"
)

func TestHTTPReportCitesStoredRuleAndKeepsAgentThree(t *testing.T) {
	ctx := t.Context()
	store, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const capture = `{"log":{"entries":[{"startedDateTime":"2026-11-18T20:20:00Z","request":
		{"method":"GET","url":"https://capture.invalid/path?session=synthetic-secret"},"response":
		{"status":200,"headers":[{"name":"Content-Type","value":"application/json"},
		{"name":"Set-Cookie","value":"sample=synthetic-secret; SameSite=None"}]}}]}}`
	observed, err := trafico.ImportHAR([]byte(capture))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(observed); err != nil {
		t.Fatal(err)
	}
	if err := store.Save([]caso.Record{{Kind: "archivo HAR", Time: "2026-11-17T21:00:00Z", Title: "Respuesta archivada",
		Source: "https://capture.invalid", Traffic: &caso.Traffic{Status: 200}, Signals: []string{"Señal anterior"}}}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := Prepare(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil || strings.Contains(string(encoded), "synthetic-secret") || strings.Contains(string(encoded), "Set-Cookie") {
		t.Fatalf("instantánea: %s, %v", encoded, err)
	}
	result, failure := claimResult(ctx, caso.AnalysisClaim{Snapshot: encoded,
		Job: caso.AnalysisJob{AgentVersion: AgentVersion, Fingerprint: snapshot.Fingerprint}})
	var report Report
	if failure != "" || json.Unmarshal(result, &report) != nil || len(report.Signals) != 4 {
		t.Fatalf("informe: %s, %s", result, failure)
	}
	for _, group := range report.Signals {
		if group.Scope != "capture.invalid" || group.Count != 1 || len(group.Evidence) != 1 {
			t.Fatalf("grupo: %+v", group)
		}
		ref := group.Evidence[0]
		if group.Value == "Señal anterior" {
			if ref.HTTPRule != "" {
				t.Fatalf("cita histórica: %+v", ref)
			}
			continue
		}
		original, err := store.RecordRevision(ctx, ref.ID, ref.Revision)
		if err != nil || ref.SHA256 != caso.Hash([]byte(capture)) || ref.SourceID != "1" || ref.Revision != 1 || ref.HTTPRule == "" ||
			!original.MatchesHTTPRule(ref.HTTPRule) {
			t.Fatalf("evidencia citada: %+v, %v", ref, err)
		}
	}
	prior := snapshot
	prior.AgentVersion = auditAgent
	prior.Records = slices.Clone(prior.Records)
	for i := range prior.Records {
		prior.Records[i].HTTPFindings = nil
	}
	prior.Fingerprint, err = prior.checksum(ctx)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err = json.Marshal(prior)
	if err != nil {
		t.Fatal(err)
	}
	result, failure = claimResult(ctx, caso.AnalysisClaim{Snapshot: encoded,
		Job: caso.AnalysisJob{AgentVersion: auditAgent, Fingerprint: prior.Fingerprint}})
	var old Report
	if failure != "" || json.Unmarshal(result, &old) != nil || old.AgentVersion != auditAgent ||
		len(old.Agents) != 5 || len(old.Signals) != len(report.Signals) || strings.Contains(string(result), `"http_rule"`) {
		t.Fatalf("informe anterior: %s, %s", result, failure)
	}
}
