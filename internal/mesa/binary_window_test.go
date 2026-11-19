package mesa

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"pavarotti/internal/analisis"
	"pavarotti/internal/caso"
	"pavarotti/internal/ingesta"
	"pavarotti/internal/terminal"
)

func TestBinaryWindowVerifiesOriginalAndMatchesTerminal(t *testing.T) {
	store, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	sample, id := saveWindowFixture(t, store)
	const host = "127.0.0.1:8443"
	handler := Handler(host, Settings{}, store, testResources)
	post := func(data []byte, length int64) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "http://"+host+"/api/registro/"+id+"/ventana-binaria?revision=1&tipo=simbolo&indice=0", bytes.NewReader(data))
		request.ContentLength = length
		request.Header.Set("Origin", "http://"+host)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	response := post(sample, int64(len(sample)))
	var web analisis.BinaryWindowReport
	if err := json.Unmarshal(response.Body.Bytes(), &web); response.Code != http.StatusOK || err != nil || web.Citation.Offset != "0x32c" ||
		web.Citation.Address != "0x112c" || web.Citation.WindowSHA256 == "" || web.Name != "observed" || len(web.Window.Instructions) != 3 {
		t.Fatalf("ventana web: estado %d, %+v, %v", response.Code, web, err)
	}
	changed := bytes.Clone(sample)
	changed[0x32c] ^= 1
	if response := post(changed, int64(len(changed))); response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("archivo alterado: %d", response.Code)
	}
	if response := post(nil, 33<<20); response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("límite de archivo: %d", response.Code)
	}
	root := t.TempDir()
	file := filepath.Join(root, "muestra.exe")
	citationPath := filepath.Join(root, "cita.json")
	if err := os.WriteFile(file, sample, 0o600); err != nil {
		t.Fatal(err)
	}
	writeCitation := func(citation analisis.BinaryWindowCitation) {
		t.Helper()
		data, err := json.Marshal(citation)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(citationPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var stdout, stderr bytes.Buffer
	run := func(args ...string) error {
		t.Helper()
		stdout.Reset()
		_, err := terminal.Run(append([]string{"ventana-binaria", "--archivo", file}, args...), &stdout, &stderr,
			func() (*caso.Store, error) { return store, nil })
		return err
	}
	writeCitation(web.Citation)
	for _, args := range [][]string{{"--id", id, "--revision", "1", "--tipo", "simbolo", "--indice", "0"}, {"--cita", citationPath}} {
		if err := run(args...); err != nil {
			t.Fatal(err)
		}
		var cli analisis.BinaryWindowReport
		if err := json.Unmarshal(stdout.Bytes(), &cli); err != nil || !reflect.DeepEqual(cli, web) {
			t.Fatalf("ventana del CLI: %+v, %v", cli, err)
		}
	}
	wrong := web.Citation
	wrong.Offset = "0x32d"
	writeCitation(wrong)
	if err := run("--cita", citationPath); !errors.Is(err, analisis.ErrBinaryWindowCitation) {
		t.Fatalf("cita alterada: %v", err)
	}
}

func saveWindowFixture(t *testing.T, store *caso.Store) ([]byte, string) {
	t.Helper()
	sample := windowFixturePE(t)
	records, err := ingesta.ParseNamed("binario", bytes.NewReader(sample), "muestra.exe")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(records); err != nil {
		t.Fatal(err)
	}
	page, err := store.Page(t.Context(), caso.PageRequest{Kind: "binario"})
	if err != nil || len(page.Rows) != 1 {
		t.Fatalf("muestra: %+v, %v", page, err)
	}
	return sample, page.Rows[0].ID
}

func windowFixturePE(t *testing.T) []byte {
	t.Helper()
	data := make([]byte, 0x416)
	order := binary.LittleEndian
	copy(data, "MZ")
	order.PutUint32(data[0x3c:], 0x80)
	copy(data[0x80:], "PE\x00\x00")
	order.PutUint16(data[0x84:], pe.IMAGE_FILE_MACHINE_AMD64)
	order.PutUint16(data[0x86:], 1)
	order.PutUint32(data[0x8c:], 0x400)
	order.PutUint32(data[0x90:], 1)
	optional := pe.OptionalHeader64{Magic: 0x20b, AddressOfEntryPoint: 0x112c, NumberOfRvaAndSizes: 16}
	order.PutUint16(data[0x94:], uint16(binary.Size(optional)))
	if err := binary.Write(bytes.NewBuffer(data[0x98:0x98]), order, optional); err != nil {
		t.Fatal(err)
	}
	header := data[0x98+binary.Size(optional):]
	copy(header, ".text")
	order.PutUint32(header[8:], 303)
	order.PutUint32(header[12:], 0x1000)
	order.PutUint32(header[16:], 0x200)
	order.PutUint32(header[20:], 0x200)
	order.PutUint32(header[36:], pe.IMAGE_SCN_MEM_EXECUTE)
	copy(data[0x200:], bytes.Repeat([]byte{0x90}, 302))
	data[0x32e] = 0xc3
	copy(data[0x400:], "observed")
	order.PutUint32(data[0x408:], 300)
	order.PutUint16(data[0x40c:], 1)
	order.PutUint16(data[0x40e:], 0x20)
	data[0x410] = 2
	order.PutUint32(data[0x412:], 4)
	return data
}
