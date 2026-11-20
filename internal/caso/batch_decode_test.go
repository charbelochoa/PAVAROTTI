package caso

import "testing"

func TestBatchDecodeReusesStorageAndClearsPreviousFields(t *testing.T) {
	first, err := decodeBatch("original", []byte(`[
		{"kind":"archivo HAR","title":"Primero","traffic":{"status":404},"signals":["Prueba"]},
		{"kind":"nota","source":"anterior.example.invalid","details":"Contenido anterior"},
		{"kind":"indicador","indicator":{"type":"dominio","value":"anterior.example.invalid"}}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	storage, original := &first[0], first[0]
	short, err := decodeBatchInto("corto", []byte(`[{"kind":"dns","title":"Actual"}]`), first)
	if err != nil {
		t.Fatal(err)
	}
	if len(short) != 1 || &short[0] != storage || short[0].ID != "corto-1" || short[0].Revision != 1 ||
		short[0].Traffic != nil || short[0].Signals != nil || short[0].Title != "Actual" {
		t.Fatalf("lote corto: %+v", short)
	}
	long, err := decodeBatchInto("nuevo", []byte(`[{"kind":"stix"},{"kind":"nota"},{"kind":"dns"}]`), short)
	if err != nil {
		t.Fatal(err)
	}
	if len(long) != 3 || &long[0] != storage || long[1].Details != "" || long[1].Source != "" ||
		long[2].Indicator != nil || long[2].ID != "nuevo-3" || long[2].Revision != 1 {
		t.Fatalf("lote largo: %+v", long)
	}
	if original.ID != "original-1" || original.Traffic.Status != 404 || original.Signals[0] != "Prueba" {
		t.Fatalf("registro original: %+v", original)
	}
}
