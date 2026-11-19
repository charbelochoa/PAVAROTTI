package caso

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

func (s *Store) postgresPage(ctx context.Context, request PageRequest, after pageCursor, limit int) ([]RecordRow, error) {
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	result, err := s.db.QueryContext(ctx, `
		WITH evidence AS (
			SELECT b.batch_key || '-' || entry.ordinal::text AS id,
			       COALESCE(entry.original->>'time', '') AS time,
			       regexp_replace(COALESCE(entry.original->>'time', ''), 'Z$', '') COLLATE "C" AS stamp,
			       COALESCE(entry.original->>'kind', '') AS kind,
			       COALESCE(edited.snapshot, entry.original) AS current_record
			FROM pavarotti_evidence_batches b
			CROSS JOIN LATERAL jsonb_array_elements(b.payload) WITH ORDINALITY AS entry(original, ordinal)
			LEFT JOIN LATERAL (
				SELECT snapshot FROM pavarotti_note_revisions
				WHERE expediente = b.expediente AND batch_key = b.batch_key AND ordinal = entry.ordinal
				  AND entry.original->>'kind' = 'nota'
				ORDER BY revision DESC LIMIT 1
			) edited ON true
			WHERE b.expediente = $1 AND ($2 = '' OR
				($2 <> 'http' AND entry.original->>'kind' = $2) OR
				($2 = 'http' AND jsonb_typeof(entry.original->'traffic') = 'object'))
		)
		SELECT id, kind, time, left(COALESCE(current_record->>'title', ''), 240),
		       left(COALESCE(current_record->>'source', ''), 360),
		       CASE WHEN $2 = 'http' THEN current_record->'traffic' END,
		       CASE WHEN $2 = 'http' AND jsonb_typeof(current_record->'signals') = 'array'
		            THEN jsonb_array_length(current_record->'signals') ELSE 0 END
		FROM evidence
		WHERE ($3 = '' OR (stamp, id COLLATE "C") < ($4::text COLLATE "C", $3::text COLLATE "C"))
		  AND ($7::integer = 0 OR left(current_record->'traffic'->>'status', 1) = $7::integer::text)
		  AND ($5 = '' OR strpos(translate(lower(concat_ws(chr(31),
		       id, kind, time, current_record->>'title', current_record->>'source',
		       current_record->>'source_id', current_record->>'sha256', current_record->>'details',
		       current_record->>'signals', current_record->'traffic'->>'method',
		       current_record->'traffic'->>'type', current_record->'traffic'->>'status',
		       current_record->'traffic'->>'millis', current_record->'traffic'->>'bucket')),
		       'ÁÉÍÓÚÜÑ', 'áéíóúüñ'), $5) > 0)
		ORDER BY stamp DESC, id COLLATE "C" DESC LIMIT $6
	`, s.expediente, request.Kind, after.ID, after.Stamp, strings.ToLower(request.Search), limit, request.HTTPClass)
	if err != nil {
		return nil, err
	}
	defer result.Close()
	rows := make([]RecordRow, 0, limit)
	for result.Next() {
		var row RecordRow
		var traffic []byte
		if err := result.Scan(&row.ID, &row.Kind, &row.Time, &row.Title, &row.Source, &traffic, &row.SignalCount); err != nil {
			return nil, err
		}
		if len(traffic) != 0 {
			if err := json.Unmarshal(traffic, &row.Traffic); err != nil {
				return nil, err
			}
		}
		rows = append(rows, row)
	}
	return rows, result.Err()
}

func (s *Store) postgresRecord(ctx context.Context, key string, ordinal int) (Record, error) {
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	var data []byte
	if err := s.db.QueryRowContext(ctx, `
		SELECT COALESCE((
			SELECT r.snapshot FROM pavarotti_note_revisions r
			WHERE r.expediente = b.expediente AND r.batch_key = b.batch_key AND r.ordinal = $3::bigint
			ORDER BY r.revision DESC LIMIT 1
		), b.payload -> ($3::integer - 1))
		FROM pavarotti_evidence_batches b
		WHERE b.expediente = $1 AND b.batch_key = $2 AND $3::bigint <= jsonb_array_length(b.payload)
	`, s.expediente, key, ordinal).Scan(&data); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Record{}, ErrNotFound
		}
		return Record{}, err
	}
	var record Record
	if err := json.Unmarshal(data, &record); err != nil {
		return Record{}, err
	}
	record.ID = key + "-" + strconv.Itoa(ordinal)
	record.Revision = max(record.Revision, 1)
	return record, nil
}
