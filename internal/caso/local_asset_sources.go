package caso

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
)

func (s *Store) localAssetCandidates(ctx context.Context, hash uint64, address netip.Addr, visit func(Record) error) error {
	unlock, err := s.lockContext(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	var batch []Record
	return s.walkLocalBatches(ctx, func(key string, entry os.DirEntry) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		version := assetBatchVersion{modified: info.ModTime(), size: info.Size()}
		index := s.assetIndex.lookup(key, version)
		var positions []int
		if index != nil {
			positions = index.candidates(hash, address)
			if len(positions) == 0 {
				return nil
			}
		}
		batch, err = s.readLocalAssetBatch(key, entry.Name(), batch)
		if err != nil {
			return err
		}
		if index == nil {
			index, err = buildAssetIndex(ctx, version, batch)
			if err != nil {
				return err
			}
			s.assetIndex.remember(key, index)
			if index != nil {
				positions = index.candidates(hash, address)
				if len(positions) == 0 {
					return nil
				}
			}
		}
		visitLatest := func(record Record) error {
			record, err := s.latestLocal(record)
			if err != nil {
				return err
			}
			return visit(record)
		}
		if len(positions) != 0 && positions[len(positions)-1] > len(batch) {
			positions = nil
		}
		return walkBatchPositions(ctx, batch, positions, visitLatest)
	})
}

func (s *Store) readLocalAssetBatch(key, name string, batch []Record) ([]Record, error) {
	data, err := os.ReadFile(filepath.Join(s.path, name))
	if err != nil {
		return nil, err
	}
	records, err := decodeBatchInto(key, data, batch)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return records, nil
}
