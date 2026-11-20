package caso

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
)

func (s *Store) postgresWalkHTTP(ctx context.Context, filter EvidenceFilter, visit func(Record) error) error {
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	starts, ends := filter.sqlDays()
	rows, err := s.db.QueryContext(ctx, `
		WITH periods AS MATERIALIZED (
			SELECT first_day, last_day FROM unnest($2::text[], $3::text[]) AS period(first_day, last_day)
		), indexed_batches AS MATERIALIZED (
			SELECT page.batch_key FROM periods JOIN pavarotti_http_page page
			  ON page.day BETWEEN periods.first_day AND periods.last_day
			WHERE $4::boolean AND page.expediente = $1
			UNION
			SELECT page.batch_key FROM pavarotti_http_page page
			WHERE $4::boolean AND page.expediente = $1 AND right(page.observed_at, 1) <> 'Z'
		)
		SELECT batch.batch_key, batch.payload
		FROM pavarotti_evidence_batches batch
		WHERE batch.expediente = $1 AND (NOT batch.http_page_indexed
		  OR ($4::boolean AND batch.batch_key IN (SELECT batch_key FROM indexed_batches))
		  OR (NOT $4::boolean AND EXISTS (
			SELECT 1 FROM pavarotti_http_page page
			WHERE page.expediente = batch.expediente AND page.batch_key = batch.batch_key
			  AND (COALESCE(cardinality($2::text[]), 0) = 0 OR right(page.observed_at, 1) <> 'Z'
			       OR EXISTS (SELECT 1 FROM periods period WHERE page.day BETWEEN period.first_day AND period.last_day))
		  )))
	`, s.expediente, starts, ends, len(starts) > 0 && filter.preferHTTPBatchIndex())
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		var data []byte
		if err := rows.Scan(&key, &data); err != nil {
			return err
		}
		if err := walkHTTPBatch(ctx, filter, key, data, visit); err != nil {
			return err
		}
	}
	return rows.Err()
}

func walkHTTPBatch(ctx context.Context, filter EvidenceFilter, key string, data []byte, visit func(Record) error) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if _, err := decoder.Token(); err != nil {
		return err
	}
	for ordinal := 1; decoder.More(); ordinal++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		var record Record
		if err := decoder.Decode(&record); err != nil {
			return err
		}
		if !filter.matches(record) {
			continue
		}
		record.ID, record.Revision = key+"-"+strconv.Itoa(ordinal), 1
		if err := visit(record); err != nil {
			return err
		}
	}
	_, err := decoder.Token()
	return err
}
