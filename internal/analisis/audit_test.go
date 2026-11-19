package analisis

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"pavarotti/internal/caso"
	"pavarotti/internal/ingesta"
)

func TestAuditSnapshotCitesThePhysicalFindingAndManifestEntry(t *testing.T) {
	ctx := t.Context()
	store, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct{ kind, name, content string }{
		{"codigo", "revisión.go", "package fixture\nimport \"net/http\"\nvar _ = http.Client{}\n"},
		{"gomod", "fixture.mod", "module sample.invalid/project\nrequire sample.invalid/catalog v1.2.3\n"},
		{"npmlock", "package-lock.json", `{"lockfileVersion":3,"packages":{"":{"dependencies":{"tool":"1.0.0"}},"node_modules/tool":{"version":"1.0.0"}}}`},
	} {
		rows, err := ingesta.ParseNamed(fixture.kind, strings.NewReader(fixture.content), `C:\private\`+fixture.name)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Save(rows); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Save([]caso.Record{{Kind: "código", Title: "Revisión de versión anterior", Details: `{"package":"fixture","imports":[],"signals":[{"line":6,"column":2,"rule":"http-limites","review":"dato-de-prueba"}]}`}}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := Prepare(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(snapshot)
	if err != nil || strings.Contains(string(data), "private") || strings.Contains(string(data), "dato-de-prueba") {
		t.Fatalf("huella de entrada con contenido ajeno: %v", err)
	}
	report, err := snapshot.Analyze(ctx)
	if err != nil || len(report.CodeFindings) != 2 || len(report.Dependencies) != 2 {
		t.Fatalf("revisión: %+v, %v", report, err)
	}
	first := report.CodeFindings[0].Evidence[0]
	if first.Line != 3 || first.Column < 1 || first.SourceID != "revisión.go" || first.Revision != 1 ||
		report.Dependencies[0].Evidence[0].Line != 2 || report.Dependencies[1].Evidence[0].Location != "#/packages/node_modules~1tool" {
		t.Fatalf("posiciones: %+v %+v", report.CodeFindings, report.Dependencies)
	}
	if original, err := store.RecordRevision(ctx, first.ID, first.Revision); err != nil || original.SHA256 != first.SHA256 {
		t.Fatalf("referencia de origen: %+v, %v", original, err)
	}
	prior := snapshot
	prior.AgentVersion = networkAgent
	prior.Records = slices.Clone(prior.Records)
	for i := range prior.Records {
		prior.Records[i].Review, prior.Records[i].Dependencies = nil, nil
	}
	prior.Fingerprint, err = prior.checksum(ctx)
	if err != nil {
		t.Fatal(err)
	}
	data, err = json.Marshal(prior)
	if err != nil {
		t.Fatal(err)
	}
	payload, failure := claimResult(ctx, caso.AnalysisClaim{Snapshot: data,
		Job: caso.AnalysisJob{AgentVersion: prior.AgentVersion, Fingerprint: prior.Fingerprint}})
	var saved Report
	if failure != "" || json.Unmarshal(payload, &saved) != nil || len(saved.Agents) != 4 ||
		saved.AgentVersion != networkAgent || saved.InputSHA256 != prior.Fingerprint || len(saved.CodeFindings)+len(saved.Dependencies) != 0 {
		t.Fatalf("compatibilidad: %s, %s", payload, failure)
	}
}
