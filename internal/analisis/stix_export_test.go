package analisis_test

import (
	"bytes"
	"strings"
	"testing"

	"pavarotti/internal/analisis"
	"pavarotti/internal/caso"
	"pavarotti/internal/ingesta"
)

func TestSTIXExchangeKeepsDNSServiceEvidencePortable(t *testing.T) {
	store, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	dns := `{"Status":0,"Answer":[{"name":"_sip._tcp.portal.invalid","type":33,"data":"0 10 5060 servicio.invalid"}]}`
	rows, err := ingesta.Parse("dns", strings.NewReader(dns))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(rows); err != nil {
		t.Fatal(err)
	}
	relations, err := analisis.RelateAsset(t.Context(), store, analisis.AssetRelationCriteria{
		AssetKey: analisis.AssetKey{Type: "dominio", Value: "_sip._tcp.portal.invalid"},
	})
	if err != nil || len(relations.Rows) != 1 || len(relations.Rows[0].Sources) != 1 {
		t.Fatalf("relación DNS SRV: %+v, %v", relations, err)
	}
	ref := relations.Rows[0].Sources[0]
	data, stats, err := analisis.ExportSTIX(t.Context(), store, nil)
	if err != nil || stats.Exported != 1 {
		t.Fatalf("exportación STIX: %+v, %v", stats, err)
	}
	imported, err := ingesta.Parse("stix", bytes.NewReader(data))
	if err != nil || len(imported) != 2 {
		t.Fatalf("reimportación: %d registros, %v", len(imported), err)
	}
	if !bytes.Contains(data, []byte(ref.ID+"@1")) || !bytes.Contains(data, []byte(`"value": "servicio.invalid"`)) ||
		bytes.Contains(data, []byte(`"value": "_sip._tcp.portal.invalid"`)) {
		t.Fatalf("procedencia y destino STIX: %s", data)
	}
}

func TestSTIXExchangeRoundTripPreservesProvenanceAndObservableLinks(t *testing.T) {
	ctx := t.Context()
	origin, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const sample = "Contenido de la muestra que no debe exportarse"
	sha := caso.Hash([]byte(sample))
	for _, fixture := range []struct{ kind, value string }{
		{"binario", sample},
		{"indicadores", sha},
		{"rdap", `{"objectClassName":"ip network","ipVersion":"v4","startAddress":"192.0.2.3","endAddress":"192.0.2.8"}`},
		{"har", `{"log":{"entries":[{"startedDateTime":"2025-01-03T10:11:12.034+02:00","request":{"method":"GET","url":"https://localhost/private?session=prueba-privada"},"response":{"status":200}}]}}`},
		{"stix", `{"type":"bundle","id":"bundle--b451dd1c-4321-4bee-99b7-7dcaf8148f8f","objects":[
			{"type":"domain-name","id":"domain-name--3c34246b-46a3-5daf-82e8-002ea3559f71","value":"source.invalid","resolves_to_refs":["ipv4-addr--115280b5-64c0-5b55-aa96-d23276647c09"]},
			{"type":"ipv4-addr","id":"ipv4-addr--115280b5-64c0-5b55-aa96-d23276647c09","value":"192.0.2.5"},
			{"type":"relationship","id":"relationship--eb544802-ddce-42ad-9405-1d6f8dae23e7","relationship_type":"related-to","source_ref":"domain-name--3c34246b-46a3-5daf-82e8-002ea3559f71","target_ref":"ipv4-addr--115280b5-64c0-5b55-aa96-d23276647c09"},
			{"type":"observed-data","id":"observed-data--948c79d4-99a2-4263-8a1a-a7eb72c793c1","first_observed":"2025-01-01T00:00:00Z","last_observed":"2025-01-02T00:00:00Z","number_observed":7,"object_refs":["domain-name--3c34246b-46a3-5daf-82e8-002ea3559f71"]}
		]}`},
	} {
		parsed, err := ingesta.Parse(fixture.kind, strings.NewReader(fixture.value))
		if err != nil {
			t.Fatal(err)
		}
		if err := origin.Save(parsed); err != nil {
			t.Fatal(err)
		}
	}
	if err := origin.Save([]caso.Record{{Kind: "nota", Time: caso.Now(), Title: "Nota privada", Details: "texto libre de la nota"}}); err != nil {
		t.Fatal(err)
	}
	data, stats, err := analisis.ExportSTIX(ctx, origin, nil)
	if err != nil || stats.Exported != 8 || stats.Excluded != 1 || bytes.Contains(data, []byte(sample)) ||
		bytes.Contains(data, []byte("prueba-privada")) || bytes.Contains(data, []byte("texto libre")) {
		t.Fatalf("exportación: %+v, %v", stats, err)
	}
	parsed, err := ingesta.Parse("stix", bytes.NewReader(data))
	if err != nil || len(parsed) != stats.Objects {
		t.Fatalf("reimportación: %d de %d, %v", len(parsed), stats.Objects, err)
	}
	destination, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if result, err := destination.SaveEvidence(ctx, parsed); err != nil || result.Imported != len(parsed) {
		t.Fatalf("guardado: %+v, %v", result, err)
	}
	if result, err := destination.SaveEvidence(ctx, parsed); err != nil || result.Duplicates != len(parsed) {
		t.Fatalf("repetición: %+v, %v", result, err)
	}
	stored, err := destination.Records()
	if err != nil {
		t.Fatal(err)
	}
	networks := make(map[string]bool)
	var relationship, linksFromObservable, countPreserved, hashPreserved, identityPreserved, harTimePreserved bool
	for _, row := range stored {
		object := row.STIXObject()
		if strings.HasPrefix(object.ID, "relationship--") {
			links, err := analisis.RelatedSTIX(ctx, destination, row.ID, 0)
			if err != nil || len(links.Rows) != 2 || !links.Rows[0].SamePackage || !links.Rows[1].SamePackage {
				t.Fatalf("relación: %+v, %v", links, err)
			}
			relationship = true
		}
		if row.Source == "source.invalid" && len(object.Refs) == 1 && object.Refs[0].Role == "resuelve a" {
			linksFromObservable = true
		}
		if object.Observation != nil && object.Observation.Count == 7 {
			countPreserved = object.Observation.First == "2025-01-01T00:00:00Z" && object.Observation.Last == "2025-01-02T00:00:00Z"
		}
		if object.Observation != nil && object.Observation.Count == 1 && object.Observation.First == "2025-01-03T08:11:12.034Z" {
			harTimePreserved = object.Observation.First == object.Observation.Last
		}
		if len(row.FileHashes) == 1 && row.FileHashes[0].Value == sha && row.SHA256 != sha {
			hashPreserved = true
		}
		for _, ref := range object.Origins {
			if id, _, _ := strings.Cut(ref.ExternalID, "@"); ref.Valid() && strings.Contains(ref.Description, sha) {
				original, err := origin.RecordRevision(ctx, id, 1)
				identityPreserved = identityPreserved || err == nil && original.Kind == "binario"
			}
		}
		networks[row.Network] = true
	}
	if !relationship || !linksFromObservable || !countPreserved || !hashPreserved || !identityPreserved || !harTimePreserved ||
		!networks["192.0.2.3/32"] || !networks["192.0.2.4/30"] || !networks["192.0.2.8/32"] {
		t.Fatalf("datos reimportados: relación=%t enlaces=%t recuento=%t huella=%t origen=%t fecha HAR=%t redes=%v",
			relationship, linksFromObservable, countPreserved, hashPreserved, identityPreserved, harTimePreserved, networks)
	}
}
