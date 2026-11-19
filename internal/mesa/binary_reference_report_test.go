package mesa

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"pavarotti/internal/analisis"
	"pavarotti/internal/caso"
	"pavarotti/internal/terminal"
	"pavarotti/internal/triaje"
)

func TestPortableBinaryReferencesOpenInAnotherCase(t *testing.T) {
	source, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	sample := windowFixturePE(t)
	order := binary.LittleEndian
	order.PutUint32(sample[0x98+16:], 0x1000)
	for _, jump := range []struct{ from, to int }{{0, 128}, {64, 300}, {128, 300}} {
		sample[0x200+jump.from] = 0xe9
		order.PutUint32(sample[0x201+jump.from:], uint32(jump.to-jump.from-5))
	}
	id := saveWindowSample(t, source, sample)
	inspection := triaje.Inspect(sample)
	first := slices.IndexFunc(inspection.Instructions, func(row triaje.Instruction) bool { return row.Offset == "0x240" })
	if first < 0 {
		t.Fatal("faltan instrucciones guardadas en la muestra")
	}
	draft := analisis.BinaryReferenceReport{Schema: analisis.BinaryReferenceSchema, RecordID: id, Revision: 1, SHA256: inspection.SHA256,
		Destination: analisis.BinaryReferenceLocation{Kind: "entrada", Path: "0.0", Address: "0x112c", Offset: "0x32c"},
		Origins: []analisis.BinaryReferenceLocation{
			{Kind: "instruccion", Index: first, Address: "0x1040", Offset: "0x240"},
			{Kind: "entrada", Path: "0", Address: "0x1080", Offset: "0x280"},
		}}
	const host = "127.0.0.1:8443"
	post := func(store *caso.Store, mode string, report analisis.BinaryReferenceReport, data []byte) *httptest.ResponseRecorder {
		t.Helper()
		var body bytes.Buffer
		form := multipart.NewWriter(&body)
		manifest, err := form.CreateFormField("informe")
		if err != nil {
			t.Fatal(err)
		}
		if err := json.NewEncoder(manifest).Encode(report); err != nil {
			t.Fatal(err)
		}
		original, err := form.CreateFormFile("archivo", "muestra.exe")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := original.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := form.Close(); err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "http://"+host+"/api/registro/"+id+"/referencias-binarias?modo="+mode, &body)
		request.Header.Set("Content-Type", form.FormDataContentType())
		request.Header.Set("Origin", "http://"+host)
		response := httptest.NewRecorder()
		Handler(host, Settings{}, store, testResources).ServeHTTP(response, request)
		return response
	}
	created := post(source, "exportar", draft, sample)
	var review analisis.BinaryReferenceReview
	if err := json.Unmarshal(created.Body.Bytes(), &review); created.Code != http.StatusOK || err != nil || review.Report.ReportSHA256 == "" ||
		len(review.Origins) != 2 || review.Origins[0].Target != "0x112c" || review.Origins[1].Target != "0x112c" ||
		review.Report.Origins[0].WindowSHA256 == review.Report.Origins[1].WindowSHA256 {
		t.Fatalf("informe generado: %d, %+v, %v", created.Code, review, err)
	}
	other, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if imported := saveWindowSample(t, other, sample); imported != id {
		t.Fatalf("la evidencia de la copia cambió de ID: %s, %s", id, imported)
	}
	opened := post(other, "verificar", review.Report, sample)
	var same analisis.BinaryReferenceReview
	if err := json.Unmarshal(opened.Body.Bytes(), &same); opened.Code != http.StatusOK || err != nil || !reflect.DeepEqual(same, review) {
		t.Fatalf("informe reabierto: %d, %+v, %v", opened.Code, same, err)
	}
	tampered := review.Report
	tampered.Origins = slices.Clone(tampered.Origins)
	tampered.Origins[0].Offset = "0x241"
	if response := post(other, "verificar", tampered, sample); response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("informe alterado: %d", response.Code)
	}
	withoutJump := draft
	withoutJump.Origins = []analisis.BinaryReferenceLocation{{Kind: "entrada", Row: 1, Address: "0x1005", Offset: "0x205"}}
	if response := post(other, "exportar", withoutJump, sample); response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("origen sin destino: %d", response.Code)
	}
	changedSample := bytes.Clone(sample)
	changedSample[0x240] ^= 1
	if response := post(other, "verificar", review.Report, changedSample); response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("archivo alterado: %d", response.Code)
	}
	folder := t.TempDir()
	reportFile, sampleFile := filepath.Join(folder, "informe.json"), filepath.Join(folder, "muestra.exe")
	encoded, err := json.Marshal(review.Report)
	if err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string][]byte{reportFile: encoded, sampleFile: sample} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var stdout, stderr bytes.Buffer
	_, err = terminal.Run([]string{"referencias-binario", "--informe", reportFile, "--archivo", sampleFile},
		&stdout, &stderr, func() (*caso.Store, error) { return other, nil })
	if err != nil {
		t.Fatalf("verificación CLI: %v, %s", err, &stderr)
	}
	var cli analisis.BinaryReferenceReport
	if err := json.Unmarshal(stdout.Bytes(), &cli); err != nil || !reflect.DeepEqual(cli, review.Report) {
		t.Fatalf("informe por CLI: %+v, %v", cli, err)
	}
}
