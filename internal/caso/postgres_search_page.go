package caso

import (
	"context"
	"strings"
)

const maxSearchBackfillBatches = 8

var escapeSearchPattern = strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`)

func (s *Store) prepareSearchPage(ctx context.Context) (bool, error) {
	const pendingQuery = `SELECT EXISTS (
		SELECT 1 FROM pavarotti_evidence_batches WHERE expediente = $1 AND NOT search_page_indexed)`
	const backfill = `
		SELECT pavarotti_store_search_batch(batch.expediente, batch.batch_key, batch.payload, batch.search_page_position)
		FROM (
			SELECT expediente, batch_key, payload, search_page_position
			FROM pavarotti_evidence_batches
			WHERE expediente = $1 AND NOT search_page_indexed
			ORDER BY batch_key
			LIMIT $2
		) batch
	`
	return s.preparePageProjection(ctx, pendingQuery, backfill, maxSearchBackfillBatches)
}

func (s *Store) postgresSearchPage(ctx context.Context, request PageRequest, after pageCursor, limit int) ([]RecordRow, error) {
	pattern := "%" + escapeSearchPattern.Replace(strings.ToLower(request.Search)) + "%"
	result, err := s.db.QueryContext(ctx, `
		SELECT d.id, d.kind, d.observed_at, d.title, d.source, d.source_id,
		       CASE WHEN $2 = 'http' THEN d.traffic END,
		       CASE WHEN $2 = 'http' THEN d.signal_count ELSE 0 END
		FROM pavarotti_search_page d
		WHERE d.expediente = $1
		  AND ($2 = '' OR ($2 = 'http' AND d.traffic IS NOT NULL) OR ($2 <> 'http' AND d.kind = $2))
		  AND ($3 = '' OR (d.stamp, d.id) < ($4::text COLLATE "C", $3::text COLLATE "C"))
		  AND ($5::integer = 0 OR left(d.traffic->>'status', 1) = $5::integer::text)
		  AND ($6 = '' OR d.kind = $6)
		  AND ($7 = '' OR d.traffic->>'method' = $7)
		  AND ($8 = '' OR left(d.observed_at, 10) COLLATE "C" >= $8)
		  AND ($9 = '' OR (length(d.observed_at) >= 10 AND left(d.observed_at, 10) COLLATE "C" <= $9))
		  AND ($10 = '' OR $10 = ANY(d.rules))
		  AND (d.document LIKE $11 OR d.partial)
		  AND CASE WHEN d.document LIKE $11 THEN true
		           WHEN d.partial THEN EXISTS (
				SELECT 1 FROM pavarotti_evidence_batches b
				WHERE b.expediente = d.expediente AND b.batch_key = d.batch_key
				  AND pavarotti_search_document(d.id, d.kind, d.observed_at,
				    COALESCE((
					SELECT snapshot FROM pavarotti_note_revisions r
					WHERE d.kind = 'nota' AND r.expediente = d.expediente AND r.batch_key = d.batch_key
					  AND r.ordinal = d.ordinal AND r.revision = d.revision
				    ), b.payload -> (d.ordinal::integer - 1))) COLLATE "C" LIKE $11
			   )
		           ELSE false END
		ORDER BY d.stamp DESC, d.id DESC LIMIT $12
	`, s.expediente, request.Kind, after.ID, after.Stamp, request.HTTPClass, request.HTTPSource,
		request.HTTPMethod, request.HTTPFrom, request.HTTPTo, request.HTTPRule, pattern, limit)
	if err != nil {
		return nil, err
	}
	return scanPostgresPage(result, limit)
}
