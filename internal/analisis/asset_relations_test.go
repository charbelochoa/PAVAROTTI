package analisis

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"pavarotti/internal/caso"
)

func TestAssetRelationsPreserveDirectionAndEvidence(t *testing.T) {
	for _, backend := range []string{"local", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			store := openScaleStore(t, backend)
			const host = "servicio.invalid"
			const ip = "192.0.2.42"
			const rangeOfIP = "192.0.2.40 – 192.0.2.49"
			const prefix = "192.0.2.32/27"
			sha256Value, sha1Value := strings.Repeat("a", 64), strings.Repeat("b", 40)
			http := &caso.Traffic{Status: 200}
			capture := []caso.Record{
				{Kind: "dns", Title: "A " + host, Time: "2026-06-03T01:00:00+02:00", Source: host + ", " + ip, SourceID: "1/respuesta/1"},
				{Kind: "dns", Title: "CNAME " + host, Time: "2026-06-02T08:00:00Z", Source: host + ", destino.invalid", SourceID: "2/respuesta/1"},
				{Kind: "dns", Title: "TXT " + host, Time: "2026-06-02T09:00:00Z", Source: host + ", engaño.invalid", SourceID: "3/respuesta/1"},
				{Kind: "dns", Title: "A " + host, Time: "2026-06-02T10:00:00Z", Source: host + ", 192.0.2.49", SourceID: "4/pregunta/1"},
				{Kind: "rdap", Title: "Dominio · " + host, Time: "2026-06-02T11:00:00Z", Source: host + ", ns1.invalid, ns1.invalid"},
				{Kind: "rdap", Title: "Red · " + rangeOfIP, Time: "2026-06-02T12:00:00Z", Network: rangeOfIP},
				{Kind: "stix", Network: prefix, Time: "2026-06-02T13:00:00Z"},
				{Kind: "stix", STIX: &caso.STIXObject{ID: "file--eb4a2517-d240-4547-b036-a12eab09d59b"},
					FileHashes: []caso.Indicator{{Type: "sha256", Value: sha256Value}, {Type: "sha1", Value: sha1Value}, {Type: "sha1", Value: sha1Value}}},
				{Kind: "archivo HAR", Source: "https://192.0.2.60", Time: "2026-06-02T14:00:00Z", Traffic: http},
				{Kind: "tráfico", Source: "https://192.0.2.61", Time: "2026-06-02T14:00:00Z", Traffic: &caso.Traffic{Status: 502},
					Signals: []string{caso.ProxyNoResponseSignal}},
				{Kind: "nota", Title: "Nota de control", Source: host + ", nota.invalid", Time: "2026-06-02T15:00:00Z"},
				{Kind: "dns", Title: "A local", Time: "2026-06-02T17:00:00Z", Source: "local, 192.0.2.67", SourceID: "5/respuesta/1"},
				{Kind: "dns", Title: "SRV _sip._tcp.servicio.invalid", Time: "2026-06-02T18:00:00Z", Source: "_sip._tcp.servicio.invalid, host.invalid", SourceID: "7/respuesta/1"},
			}
			for index := range 6 {
				capture = append(capture, caso.Record{Kind: "dns", Title: "A " + host, Source: host + ", " + ip,
					Time: fmt.Sprintf("2026-06-02T01:%02d:00Z", index), SourceID: fmt.Sprintf("6/respuesta/%d", index+1)})
			}
			if err := store.Save(capture); err != nil {
				t.Fatal(err)
			}
			ctx := t.Context()
			find := func(report AssetRelationsReport, kind, value, direction string) AssetRelation {
				t.Helper()
				for _, row := range report.Rows {
					if row.Kind == kind && row.Value == value && row.Direction == direction {
						return row
					}
				}
				t.Fatalf("relación %s %s %s: %+v", kind, value, direction, report.Rows)
				return AssetRelation{}
			}
			domain, err := RelateAsset(ctx, store, AssetRelationCriteria{AssetKey: AssetKey{Type: "dominio", Value: "SERVICIO.invalid."},
				From: "2026-06-02", To: "2026-06-02"})
			if err != nil || domain.Schema != AssetRelationsSchema || domain.Criteria.Value != host || domain.Records != 9 || len(domain.Rows) != 3 {
				t.Fatalf("dominio: %+v, %v", domain, err)
			}
			resolution := domain.Rows[0]
			if resolution.Kind != "dns-a" || resolution.Value != ip || resolution.Direction != "saliente" || resolution.Count != 7 ||
				len(resolution.Sources) != 5 || resolution.First != "2026-06-02T01:00:00Z" || resolution.Last != "2026-06-02T23:00:00Z" ||
				resolution.Sources[0].Time != capture[0].Time {
				t.Fatalf("resoluciones y orden de citas: %+v", resolution)
			}
			ref := resolution.Sources[0]
			record, err := store.RecordRevision(ctx, ref.ID, ref.Revision)
			if err != nil || record.SourceID != "1/respuesta/1" {
				t.Fatalf("cita de respuesta DNS: %+v, %v", record, err)
			}
			if find(domain, "rdap-ns", "ns1.invalid", "saliente").Count != 1 {
				t.Fatal("RDAP contó dos veces el mismo servidor")
			}
			find(domain, "dns-cname", "destino.invalid", "saliente")
			address, err := RelateAsset(ctx, store, AssetRelationCriteria{AssetKey: AssetKey{Type: "ipv4", Value: ip}})
			if err != nil || len(address.Rows) != 3 {
				t.Fatalf("ficha IP: %+v, %v", address, err)
			}
			find(address, "dns-a", host, "entrante")
			find(address, "rdap-cobertura", rangeOfIP, "entrante")
			find(address, "stix-cobertura", prefix, "entrante")
			network, err := RelateAsset(ctx, store, AssetRelationCriteria{AssetKey: AssetKey{Type: "red", Value: "192.0.2.42/27"}})
			if err != nil || len(network.Rows) != 2 {
				t.Fatalf("red: %+v, %v", network, err)
			}
			find(network, "ip-observada", ip, "saliente")
			find(network, "ip-observada", "192.0.2.60", "saliente")
			fingerprints, err := RelateAsset(ctx, store, AssetRelationCriteria{AssetKey: AssetKey{Type: "sha256", Value: sha256Value}})
			if err != nil || len(fingerprints.Rows) != 1 || find(fingerprints, "stix-huella", sha1Value, "compartida").Count != 1 {
				t.Fatalf("huellas de un mismo archivo: %+v, %v", fingerprints, err)
			}
			single := AssetKey{Type: "dominio", Value: "local"}
			linked, err := RelateAsset(ctx, store, AssetRelationCriteria{AssetKey: single})
			if err != nil || len(linked.Rows) != 1 {
				t.Fatalf("nombre interno: %+v, %v", linked, err)
			}
			if card, err := DescribeAsset(ctx, store, AssetQuery{AssetKey: single}); err != nil || card.Count != 1 {
				t.Fatalf("ficha del nombre interno: %+v, %v", card, err)
			}
			service := AssetKey{Type: "dominio", Value: "_sip._tcp.servicio.invalid"}
			linked, err = RelateAsset(ctx, store, AssetRelationCriteria{AssetKey: service})
			if err != nil || len(linked.Rows) != 1 {
				t.Fatalf("SRV: %+v, %v", linked, err)
			}
			find(linked, "dns-srv", "host.invalid", "saliente")
			if card, err := DescribeAsset(ctx, store, AssetQuery{AssetKey: service}); err != nil || card.Count != 1 {
				t.Fatalf("ficha SRV: %+v, %v", card, err)
			}
			if _, err := RelateAsset(ctx, store, AssetRelationCriteria{AssetKey: single, From: "2026-06-02"}); !errors.Is(err, ErrAssetQuery) {
				t.Fatalf("periodo incompleto: %v", err)
			}
		})
	}
}

func TestAssetRelationsKeepsMostSupportedRows(t *testing.T) {
	store, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	const host = "origen.invalid"
	records := make([]caso.Record, 0, 103)
	for index := range 102 {
		records = append(records, caso.Record{Kind: "dns", Title: "A " + host, SourceID: "1/respuesta/1",
			Source: fmt.Sprintf("%s, 192.0.2.%d", host, index), Time: "2026-06-02T12:00:00Z"})
	}
	records = append(records, records[101])
	if err := store.Save(records); err != nil {
		t.Fatal(err)
	}
	report, err := RelateAsset(t.Context(), store, AssetRelationCriteria{AssetKey: AssetKey{Type: "dominio", Value: host}})
	if err != nil || len(report.Rows) != 100 || report.OmittedRows != 2 || report.Records != 103 ||
		report.Rows[0].Value != "192.0.2.101" || report.Rows[0].Count != 2 ||
		len(report.Rows[0].Sources) != 2 || report.Rows[0].Sources[0].ID == report.Rows[0].Sources[1].ID {
		t.Fatalf("relaciones con más fuentes: %d visibles, %d omitidas, %d registros, %v",
			len(report.Rows), report.OmittedRows, report.Records, err)
	}
}
