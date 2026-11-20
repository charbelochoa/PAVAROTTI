package caso

import (
	"context"
	"database/sql"
	"encoding/json"
	"maps"
	"net/netip"
	"slices"
	"strconv"
)

const maxSparseAssetRows = 32

type postgresAssetSelection struct {
	uncached map[string]assetBatchVersion
	dense    []string
	sparse   []string
	ordinals []int
}

func (s *Store) postgresAssetCandidates(ctx context.Context, asset AssetKey, address netip.Addr, visit func(Record) error) error {
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	selection, err := s.postgresAssetSelection(ctx, tx, asset, address)
	if err != nil {
		return err
	}
	if len(selection.uncached) != 0 {
		keys := slices.Collect(maps.Keys(selection.uncached))
		if err := s.postgresBatches(ctx, tx, keys, func(key string, records, edits []Record) error {
			index, err := buildAssetIndex(ctx, selection.uncached[key], records)
			if err != nil {
				return err
			}
			s.assetIndex.remember(key, index)
			var positions []int
			if index != nil {
				positions = index.candidates(asset, address)
				if len(positions) == 0 {
					return nil
				}
			}
			applyPostgresEdits(records, edits)
			return walkBatchPositions(ctx, records, positions, visit)
		}); err != nil {
			return err
		}
	}
	if len(selection.dense) != 0 {
		if err := s.postgresBatches(ctx, tx, selection.dense, func(_ string, records, edits []Record) error {
			applyPostgresEdits(records, edits)
			return walkBatchPositions(ctx, records, nil, visit)
		}); err != nil {
			return err
		}
	}
	if len(selection.sparse) != 0 {
		if err := s.postgresSparseAssetRows(ctx, tx, selection, visit); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) postgresAssetSelection(ctx context.Context, tx *sql.Tx, asset AssetKey, address netip.Addr) (postgresAssetSelection, error) {
	selection := postgresAssetSelection{uncached: make(map[string]assetBatchVersion)}
	rows, err := tx.QueryContext(ctx, `SELECT batch_key, xmin::text FROM pavarotti_evidence_batches WHERE expediente = $1`, s.expediente)
	if err != nil {
		return selection, err
	}
	defer rows.Close()
	for rows.Next() {
		var key, row string
		if err := rows.Scan(&key, &row); err != nil {
			return selection, err
		}
		version := assetBatchVersion{row: row}
		index := s.assetIndex.lookup(key, version)
		if index == nil {
			selection.uncached[key] = version
			continue
		}
		positions := index.candidates(asset, address)
		if len(positions) > maxSparseAssetRows {
			selection.dense = append(selection.dense, key)
			continue
		}
		for _, ordinal := range positions {
			selection.sparse = append(selection.sparse, key)
			selection.ordinals = append(selection.ordinals, ordinal)
		}
	}
	return selection, rows.Err()
}

func (s *Store) postgresSparseAssetRows(ctx context.Context, tx *sql.Tx, selection postgresAssetSelection, visit func(Record) error) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT b.batch_key, picked.ordinal, b.payload -> (picked.ordinal - 1), edited.snapshot
		FROM unnest($2::text[], $3::int[]) AS picked(batch_key, ordinal)
		JOIN pavarotti_evidence_batches b ON b.expediente = $1 AND b.batch_key = picked.batch_key
		LEFT JOIN LATERAL (
			SELECT snapshot FROM pavarotti_note_revisions
			WHERE expediente = b.expediente AND batch_key = b.batch_key AND ordinal = picked.ordinal
			ORDER BY revision DESC LIMIT 1
		) edited ON true`, s.expediente, selection.sparse, selection.ordinals)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		var ordinal int
		var body, edit []byte
		if err := rows.Scan(&key, &ordinal, &body, &edit); err != nil {
			return err
		}
		var record Record
		if err := json.Unmarshal(body, &record); err != nil {
			return err
		}
		record.ID, record.Revision = key+"-"+strconv.Itoa(ordinal), 1
		if len(edit) != 0 {
			var latest Record
			if err := json.Unmarshal(edit, &latest); err != nil {
				return err
			}
			if latest.ID == record.ID {
				record = latest
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := visit(record); err != nil {
			return err
		}
	}
	return rows.Err()
}
