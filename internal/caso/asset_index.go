package caso

import (
	"cmp"
	"context"
	"hash/maphash"
	"net/netip"
	"slices"
	"sync"
	"time"
)

const maxAssetIndexBytes = 32 << 20
const maxAssetIndexBatches = 4096
const assetPostingBytes = 16

var assetHashSeed = maphash.MakeSeed()

type assetBatchVersion struct {
	modified time.Time
	size     int64
	row      string
}

type assetBatchIndex struct {
	version  assetBatchVersion
	weight   int
	postings []assetPosting
	notes    []int
	networks []assetBatchNetwork
}

type assetPosting struct {
	hash    uint64
	ordinal int
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
	index := &assetBatchIndex{version: version, weight: 256}
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
			capacity := cap(index.postings)
			index.postings = append(index.postings, assetPosting{maphash.Comparable(assetHashSeed, key), ordinal})
			index.weight += (cap(index.postings) - capacity) * assetPostingBytes
		})
	}
	if index.weight > maxAssetIndexBytes {
		return nil, nil
	}
	slices.SortFunc(index.postings, func(a, b assetPosting) int {
		if order := cmp.Compare(a.hash, b.hash); order != 0 {
			return order
		}
		return cmp.Compare(a.ordinal, b.ordinal)
	})
	index.postings = slices.Compact(index.postings)
	return index, ctx.Err()
}

func (index *assetBatchIndex) candidates(hash uint64, address netip.Addr) []int {
	start, _ := slices.BinarySearchFunc(index.postings, hash, func(posting assetPosting, hash uint64) int {
		return cmp.Compare(posting.hash, hash)
	})
	end := start
	for end < len(index.postings) && index.postings[end].hash == hash {
		end++
	}
	positions := make([]int, end-start, end-start+len(index.notes))
	for index, posting := range index.postings[start:end] {
		positions[index] = posting.ordinal
	}
	if len(index.notes) == 0 && (!address.IsValid() || len(index.networks) == 0) {
		return positions
	}
	positions = append(positions, index.notes...)
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
	address, _ := netip.ParseAddr(key.Value)
	hash := maphash.Comparable(assetHashSeed, key)
	if s.db != nil {
		return s.postgresAssetCandidates(ctx, hash, address, visit)
	}
	return s.localAssetCandidates(ctx, hash, address, visit)
}

func walkBatchPositions(ctx context.Context, records []Record, positions []int, visit func(Record) error) error {
	if positions == nil {
		for _, record := range records {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := visit(record); err != nil {
				return err
			}
		}
		return nil
	}
	for _, ordinal := range positions {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := visit(records[ordinal-1]); err != nil {
			return err
		}
	}
	return nil
}
