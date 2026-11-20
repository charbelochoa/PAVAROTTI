package caso

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
)

func (s *Store) localAssetCandidates(ctx context.Context, asset AssetKey, address netip.Addr, visit func(Record) error) error {
	unlock, err := s.lockContext(ctx)
	if err != nil {
		return err
	}
	defer unlock()
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
		var records []Record
		if index == nil {
			records, err = s.readLocalAssetBatch(key, entry.Name())
			if err != nil {
				return err
			}
			index, err = buildAssetIndex(ctx, version, records)
			if err != nil {
				return err
			}
			s.assetIndex.remember(key, index)
		}
		var positions []int
		if index != nil {
			positions = index.candidates(asset, address)
			if len(positions) == 0 {
				return nil
			}
		}
		if records == nil {
			records, err = s.readLocalAssetBatch(key, entry.Name())
			if err != nil {
				return err
			}
		}
		visitLatest := func(record Record) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			record, err := s.latestLocal(record)
			if err != nil {
				return err
			}
			return visit(record)
		}
		if index == nil || positions[len(positions)-1] > len(records) {
			for _, record := range records {
				if err := visitLatest(record); err != nil {
					return err
				}
			}
			return nil
		}
		for _, ordinal := range positions {
			if err := visitLatest(records[ordinal-1]); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) readLocalAssetBatch(key, name string) ([]Record, error) {
	data, err := os.ReadFile(filepath.Join(s.path, name))
	if err != nil {
		return nil, err
	}
	records, err := decodeBatch(key, data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return records, nil
}
