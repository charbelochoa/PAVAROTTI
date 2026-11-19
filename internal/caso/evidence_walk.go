package caso

import (
	"context"
	"encoding/json"
	"strconv"
	"time"
)

type EvidencePeriod struct {
	Start time.Time
	End   time.Time
}

func (period EvidencePeriod) Includes(stamp time.Time) bool {
	return !stamp.Before(period.Start) && stamp.Before(period.End)
}

type EvidenceFilter struct {
	HTTP    bool
	Periods []EvidencePeriod
}

func (s *Store) WalkHTTP(ctx context.Context, visit func(Record) error) error {
	return s.WalkFiltered(ctx, EvidenceFilter{HTTP: true}, visit)
}

func (s *Store) WalkFiltered(ctx context.Context, filter EvidenceFilter, visit func(Record) error) error {
	if len(filter.Periods) == 0 && !filter.HTTP {
		return s.Walk(ctx, visit)
	}
	if s.db == nil {
		return s.walkLocalFiltered(ctx, !filter.HTTP, filter, visit)
	}
	return s.postgresWalkFiltered(ctx, filter, visit)
}

func (filter EvidenceFilter) matches(record Record) bool {
	if filter.HTTP && record.Traffic == nil {
		return false
	}
	if len(filter.Periods) == 0 {
		return true
	}
	stamp, err := time.Parse(time.RFC3339Nano, record.Time)
	if err != nil {
		return false
	}
	for _, period := range filter.Periods {
		if period.Includes(stamp) {
			return true
		}
	}
	return false
}

func (filter EvidenceFilter) sqlDays() ([]string, []string) {
	var starts, ends []string
	for _, period := range filter.Periods {
		from, last := period.Start.UTC(), period.End.Add(-time.Nanosecond).UTC()
		if !period.Start.Before(period.End) || from.Year() < 1 || last.Year() > 9999 {
			return nil, nil
		}
		starts, ends = append(starts, from.Format(time.DateOnly)), append(ends, last.Format(time.DateOnly))
	}
	return starts, ends
}

func (s *Store) postgresWalkFiltered(ctx context.Context, filter EvidenceFilter, visit func(Record) error) error {
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	starts, ends := filter.sqlDays()
	rows, err := s.db.QueryContext(ctx, `
		SELECT b.batch_key, entry.ordinal, COALESCE(edited.revision, 1), COALESCE(edited.snapshot, entry.item)
		FROM pavarotti_evidence_batches b
		CROSS JOIN LATERAL jsonb_array_elements(b.payload) WITH ORDINALITY AS entry(item, ordinal)
		LEFT JOIN LATERAL (
			SELECT revision, snapshot FROM pavarotti_note_revisions
			WHERE NOT $2::boolean AND entry.item->>'kind' = 'nota'
			  AND expediente = b.expediente AND batch_key = b.batch_key AND ordinal = entry.ordinal
			ORDER BY revision DESC LIMIT 1
		) edited ON true
		WHERE b.expediente = $1 AND (NOT $2::boolean OR jsonb_typeof(entry.item->'traffic') = 'object')
		  AND (COALESCE(cardinality($3::text[]), 0) = 0 OR right(COALESCE(entry.item->>'time', ''), 1) <> 'Z'
		       OR EXISTS (SELECT 1 FROM unnest($3::text[], $4::text[]) AS period(first_day, last_day)
		                  WHERE left(entry.item->>'time', 10) COLLATE "C" BETWEEN period.first_day AND period.last_day))
	`, s.expediente, filter.HTTP, starts, ends)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		var ordinal, revision int
		var data []byte
		if err := rows.Scan(&key, &ordinal, &revision, &data); err != nil {
			return err
		}
		var record Record
		if err := json.Unmarshal(data, &record); err != nil {
			return err
		}
		if !filter.matches(record) {
			continue
		}
		record.ID, record.Revision = key+"-"+strconv.Itoa(ordinal), revision
		if err := visit(record); err != nil {
			return err
		}
	}
	return rows.Err()
}
