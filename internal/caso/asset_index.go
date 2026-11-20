package caso

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

const maxAssetIndexBytes = 32 << 20
const maxAssetIndexBatches = 4096

type assetBatchVersion struct {
	modified time.Time
	size     int64
	row      string
}

type assetBatchIndex struct {
	version  assetBatchVersion
	weight   int
	keys     map[AssetKey]int
	ordinals [][]int
	notes    []int
	networks []assetBatchNetwork
}

type assetBatchNetwork struct {
	ordinal int
	network AssetNetwork
}

type assetIndexCache struct {
	mu      sync.Mutex
	weight  int
	batches map[string]*assetBatchIndex
}

func (cache *assetIndexCache) lookup(key string, version assetBatchVersion) *assetBatchIndex {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if batch := cache.batches[key]; batch != nil && batch.version == version {
		return batch
	}
	return nil
}

func (cache *assetIndexCache) remember(key string, batch *assetBatchIndex) {
	if batch == nil {
		return
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.batches == nil {
		cache.batches = make(map[string]*assetBatchIndex)
	}
	if previous := cache.batches[key]; previous != nil {
		if previous.version == batch.version {
			return
		}
		cache.weight -= previous.weight
		delete(cache.batches, key)
	}
	if cache.weight+batch.weight > maxAssetIndexBytes || len(cache.batches) >= maxAssetIndexBatches {
		return
	}
	cache.batches[key] = batch
	cache.weight += batch.weight
}

func buildAssetIndex(ctx context.Context, version assetBatchVersion, records []Record) (*assetBatchIndex, error) {
	index := &assetBatchIndex{version: version, weight: 256, keys: make(map[AssetKey]int)}
	for position, record := range records {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if index.weight > maxAssetIndexBytes {
			return nil, nil
		}
		ordinal := position + 1
		if record.Kind == "nota" {
			index.notes = append(index.notes, ordinal)
			index.weight += 16
			continue
		}
		network := RecordNetwork(record)
		if network.Value != "" {
			index.networks = append(index.networks, assetBatchNetwork{ordinal: ordinal, network: network})
			index.weight += 256 + len(network.Value)
		}
		RecordAssets(record, network, "", func(key AssetKey, _ string) {
			if index.weight > maxAssetIndexBytes {
				return
			}
			slot, found := index.keys[key]
			if !found {
				slot = len(index.ordinals)
				index.keys[AssetKey{Type: strings.Clone(key.Type), Value: strings.Clone(key.Value)}] = slot
				index.ordinals = append(index.ordinals, nil)
				index.weight += 192 + len(key.Type) + len(key.Value)
			}
			positions := index.ordinals[slot]
			if len(positions) == 0 || positions[len(positions)-1] != ordinal {
				index.ordinals[slot] = append(positions, ordinal)
				index.weight += 16
			}
		})
	}
	if index.weight > maxAssetIndexBytes {
		return nil, nil
	}
	return index, nil
}

func (index *assetBatchIndex) candidates(key AssetKey, address netip.Addr) []int {
	var direct []int
	if slot, found := index.keys[key]; found {
		direct = index.ordinals[slot]
	}
	if len(index.notes) == 0 && (!address.IsValid() || len(index.networks) == 0) {
		return direct
	}
	positions := slices.Concat(direct, index.notes)
	if address.IsValid() {
		for _, cover := range index.networks {
			if cover.network.Contains(address) {
				positions = append(positions, cover.ordinal)
			}
		}
	}
	slices.Sort(positions)
	return slices.Compact(positions)
}

func (s *Store) WalkAssetCandidates(ctx context.Context, key AssetKey, visit func(Record) error) error {
	if s.db != nil {
		return s.postgresWalk(ctx, visit)
	}
	address, _ := netip.ParseAddr(key.Value)
	return s.localAssetCandidates(ctx, key, address, visit)
}
