package caso

import (
	"fmt"
	"hash/maphash"
	"net/netip"
	"slices"
	"testing"
)

func TestAssetIndexStoresDistinctKeysWithinCacheBudget(t *testing.T) {
	records := make([]Record, 1000)
	for index := range records {
		records[index] = Record{Kind: "dns", SourceID: "captura/respuesta/1",
			Source: fmt.Sprintf("activo-%d.example.invalid, 2001:db8:1::%x", index, index+1)}
	}
	version := assetBatchVersion{row: "1"}
	index, err := buildAssetIndex(t.Context(), version, records)
	if err != nil || index == nil {
		t.Fatalf("índice: %v", err)
	}
	if len(index.postings) != 2000 || index.weight < cap(index.postings)*assetPostingBytes || index.weight > 48<<10 {
		t.Fatalf("índice: %d entradas, %d bytes, capacidad %d", len(index.postings), index.weight, cap(index.postings))
	}
	cache := assetIndexCache{}
	for number := range 180 {
		key := fmt.Sprint(number)
		cache.remember(key, index)
		if cache.lookup(key, version) == nil {
			t.Fatalf("lote %s fuera del presupuesto", key)
		}
	}
	if len(cache.batches) != 180 || cache.weight > maxAssetIndexBytes {
		t.Fatalf("caché: %d lotes, %d bytes", len(cache.batches), cache.weight)
	}
	key := AssetKey{Type: "dominio", Value: "activo-999.example.invalid"}
	if got := index.candidates(maphash.Comparable(assetHashSeed, key), netip.Addr{}); !slices.Equal(got, []int{1000}) {
		t.Fatalf("candidatos para %s: %v", key.Value, got)
	}
}

func TestAssetIndexReturnsEachCandidateOnce(t *testing.T) {
	digest := Indicator{Type: "sha256", Value: Hash([]byte("muestra"))}
	index, err := buildAssetIndex(t.Context(), assetBatchVersion{}, []Record{
		{Kind: "nota"},
		{Kind: "stix", FileHashes: []Indicator{digest, digest}, Network: "192.0.2.0/24"},
		{Kind: "stix", FileHashes: []Indicator{digest}},
	})
	if err != nil || index == nil {
		t.Fatalf("índice: %v", err)
	}
	hash := maphash.Comparable(assetHashSeed, AssetKey(digest))
	if got := index.candidates(hash, netip.MustParseAddr("192.0.2.42")); !slices.Equal(got, []int{1, 2, 3}) {
		t.Fatalf("candidatos duplicados o fuera de orden: %v", got)
	}
}
