package caso

import (
	"context"
	"encoding/json"
	"strconv"
)

type Summary struct {
	Total   int            `json:"total"`
	Traffic int            `json:"traffic"`
	Signals int            `json:"signals"`
	Status  map[string]int `json:"status"`
	MIME    map[string]int `json:"mime"`
	Bucket  map[string]int `json:"bucket"`
}

func (s *Store) Summary(ctx context.Context) (Summary, error) {
	if s.db != nil {
		return s.postgresSummary(ctx)
	}
	value := Summary{Status: make(map[string]int), MIME: make(map[string]int), Bucket: make(map[string]int)}
	err := s.walkLocal(ctx, false, func(record Record) error {
		value.Total++
		value.Signals += len(record.Signals)
		if traffic := record.Traffic; traffic != nil {
			value.Traffic++
			value.Status[strconv.Itoa(traffic.Status)]++
			value.MIME[traffic.Type]++
			value.Bucket[strconv.FormatInt(traffic.Bucket, 10)]++
		}
		return nil
	})
	return value, err
}

func (s *Store) postgresSummary(ctx context.Context) (Summary, error) {
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	var value Summary
	var status, mime, bucket []byte
	err := s.db.QueryRowContext(ctx, `
		WITH evidence AS (
			SELECT item->'traffic'->>'status' AS status,
			       COALESCE(item->'traffic'->>'type', '') AS mime,
			       COALESCE(item->'traffic'->>'bucket', '0') AS bucket,
			       CASE WHEN jsonb_typeof(item->'signals') = 'array'
			            THEN jsonb_array_length(item->'signals') ELSE 0 END AS signals
			FROM pavarotti_evidence_batches batch
			CROSS JOIN LATERAL jsonb_array_elements(batch.payload) item
			WHERE batch.expediente = $1
		)
		SELECT count(*), count(status), COALESCE(sum(signals), 0),
		       COALESCE((SELECT jsonb_object_agg(status, n)
		                 FROM (SELECT status, count(*) n FROM evidence WHERE status IS NOT NULL GROUP BY status) g), '{}'),
		       COALESCE((SELECT jsonb_object_agg(mime, n)
		                 FROM (SELECT mime, count(*) n FROM evidence WHERE status IS NOT NULL GROUP BY mime) g), '{}'),
		       COALESCE((SELECT jsonb_object_agg(bucket, n)
		                 FROM (SELECT bucket, count(*) n FROM evidence WHERE status IS NOT NULL GROUP BY bucket) g), '{}')
		FROM evidence
	`, s.expediente).Scan(&value.Total, &value.Traffic, &value.Signals, &status, &mime, &bucket)
	if err != nil {
		return Summary{}, err
	}
	for _, entry := range []struct {
		data []byte
		dest *map[string]int
	}{{status, &value.Status}, {mime, &value.MIME}, {bucket, &value.Bucket}} {
		if err := json.Unmarshal(entry.data, entry.dest); err != nil {
			return Summary{}, err
		}
	}
	return value, nil
}
