package caso

import (
	"context"
	"encoding/json"
	"strconv"
)

func (s *Store) WalkHTTP(ctx context.Context, visit func(Record) error) error {
	if s.db == nil {
		return s.walkLocal(ctx, false, func(record Record) error {
			if record.Traffic == nil {
				return nil
			}
			return visit(record)
		})
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `
		SELECT b.batch_key, entry.ordinal, entry.item
		FROM pavarotti_evidence_batches b
		CROSS JOIN LATERAL jsonb_array_elements(b.payload) WITH ORDINALITY AS entry(item, ordinal)
		WHERE b.expediente = $1 AND jsonb_typeof(entry.item->'traffic') = 'object'`, s.expediente)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		var ordinal int
		var data []byte
		if err := rows.Scan(&key, &ordinal, &data); err != nil {
			return err
		}
		var record Record
		if err := json.Unmarshal(data, &record); err != nil {
			return err
		}
		record.ID, record.Revision = key+"-"+strconv.Itoa(ordinal), 1
		if err := visit(record); err != nil {
			return err
		}
	}
	return rows.Err()
}
