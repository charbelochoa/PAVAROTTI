package analisis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"pavarotti/internal/caso"
)

func TestAgentReport(t *testing.T) {
	const hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const token = "sensible-super-secreto"
	const hsts = "HTTPS sin cabecera HSTS"
	records := []caso.Record{
		{Kind: "hallazgo", Time: "2026-11-18T12:00:00Z", Title: "Observación en expediente", Source: "API.example., api.example:443, 192.0.2.1", SourceID: "h-1", SHA256: hash},
		{Kind: "archivo HAR", Time: "2026-11-18T07:00:01-06:00", Title: "Respuesta A", Source: "https://user:" + token + "@Api.EXAMPLE:443/?token=" + token, SourceID: "1", SHA256: hash, Traffic: &caso.Traffic{Status: 200}, Signals: []string{hsts, hsts}},
		{Kind: "archivo HAR", Time: "2026-11-18T13:00:00Z", Title: "Respuesta B", Source: "https://api.example", SourceID: "2", SHA256: strings.ToUpper(hash), Traffic: &caso.Traffic{Status: 200}, Signals: []string{hsts}},
		{Kind: "nota", Time: "sin fecha", Title: "Referencia", Source: "no es un dominio", Details: "no se vuelca " + token, SHA256: "inválida"},
	}
	report, err := Analyze(context.Background(), records)
	if err != nil {
		t.Fatal(err)
	}
	if report.Records != 4 || len(report.Agents) != 5 || len(report.Assets) != 2 || len(report.Timeline) != 3 {
		t.Fatalf("recuentos incorrectos: %+v", report)
	}
	if group := report.Assets[0]; group.Value != "api.example" || group.Count != 3 || group.Evidence[0].SourceID != "1" {
		t.Fatalf("inventario: %+v", group)
	}
	if len(report.Hashes) != 2 || report.Hashes[0].Value != hash || report.Hashes[0].Count != 2 || report.Hashes[0].Scope != "archivo HAR" {
		t.Fatalf("alcance de las huellas: %+v", report.Hashes)
	}
	if len(report.Signals) != 1 || report.Signals[0].Count != 2 || report.Signals[0].Scope != "api.example" {
		t.Fatalf("señales agrupadas: %+v", report.Signals)
	}
	if len(report.Responses) != 1 || report.Responses[0].Value != "200" || report.Responses[0].Count != 2 {
		t.Fatalf("respuestas agrupadas: %+v", report.Responses)
	}
	if report.Timeline[0].SourceID != "1" || report.Timeline[1].SourceID != "2" {
		t.Fatalf("orden de zonas horarias: %+v", report.Timeline)
	}
	raw, err := json.Marshal(report)
	if err != nil || strings.Contains(string(raw), token) || strings.Contains(report.Text(), token) {
		t.Fatalf("el informe incluyó datos de una URL o del cuerpo: %s", raw)
	}
}

func TestLimits(t *testing.T) {
	records := make([]caso.Record, groupLimit+15)
	for index := range records {
		records[index] = caso.Record{
			Kind: "nota", Time: time.Unix(int64(index)+1, 0).UTC().Format(time.RFC3339Nano),
			Source: fmt.Sprintf("host-%03d.example, recurrente.example", index),
		}
	}
	report, err := Analyze(context.Background(), records)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Assets) != groupLimit || len(report.Assets[0].Evidence) != referenceLimit ||
		report.Assets[0].Value != "recurrente.example" || report.Assets[0].Count != len(records) ||
		len(report.Timeline) != timelineLimit {
		t.Fatalf("límites de salida: %d grupos, %d eventos", len(report.Assets), len(report.Timeline))
	}
	if report.Agents[0].Matched != len(records)+1 {
		t.Fatalf("el total debe ser independiente del límite visual: %+v", report.Agents[0])
	}
	if _, err = Analyze(context.Background(), make([]caso.Record, RecordLimit+1)); !errors.Is(err, ErrLimit) {
		t.Fatalf("límite de entrada: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = Analyze(ctx, records); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelación: %v", err)
	}
}
