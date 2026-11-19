package caso

import (
	"context"
	"database/sql"
)

const maxHTTPBackfillBatches = 256

func migrateHTTPPageIndex(ctx context.Context, tx *sql.Tx) error {
	var installed bool
	if err := tx.QueryRowContext(ctx, `SELECT to_regclass('pavarotti_http_page') IS NOT NULL`).Scan(&installed); err != nil {
		return err
	}
	if installed {
		return nil
	}
	_, err := tx.ExecContext(ctx, `
		ALTER TABLE pavarotti_evidence_batches ADD COLUMN http_page_indexed BOOLEAN NOT NULL DEFAULT false;
		CREATE INDEX pavarotti_http_page_pending
		ON pavarotti_evidence_batches (expediente, batch_key) WHERE NOT http_page_indexed;

		CREATE TABLE pavarotti_http_page (
			expediente TEXT NOT NULL,
			batch_key TEXT NOT NULL,
			ordinal BIGINT NOT NULL,
			id TEXT COLLATE "C" NOT NULL,
			stamp TEXT COLLATE "C" NOT NULL,
			observed_at TEXT NOT NULL,
			day TEXT COLLATE "C" NOT NULL,
			kind TEXT NOT NULL,
			title TEXT NOT NULL,
			source TEXT NOT NULL,
			source_id TEXT NOT NULL,
			traffic JSONB NOT NULL,
			signal_count INTEGER NOT NULL,
			rules TEXT[] NOT NULL,
			PRIMARY KEY (expediente, batch_key, ordinal),
			FOREIGN KEY (expediente, batch_key)
				REFERENCES pavarotti_evidence_batches (expediente, batch_key) ON DELETE CASCADE
		);
		CREATE INDEX pavarotti_http_page_order ON pavarotti_http_page (expediente, stamp DESC, id DESC);
		CREATE INDEX pavarotti_http_page_day ON pavarotti_http_page (expediente, day);

		CREATE FUNCTION pavarotti_store_http_page_batch(case_name TEXT, key TEXT, records JSONB) RETURNS VOID
		LANGUAGE SQL AS $build$
			INSERT INTO pavarotti_http_page (
				expediente, batch_key, ordinal, id, stamp, observed_at, day, kind, title, source, source_id,
				traffic, signal_count, rules)
			SELECT case_name, key, entry.ordinal, key || '-' || entry.ordinal::text,
				CASE WHEN right(body.observed_at, 1) = 'Z' THEN left(body.observed_at, -1) ELSE body.observed_at END,
				body.observed_at, left(body.observed_at, 10), body.kind,
				left(COALESCE(entry.item->>'title', ''), 240), left(COALESCE(entry.item->>'source', ''), 360),
				CASE WHEN body.kind = 'binario' THEN left(COALESCE(entry.item->>'source_id', ''), 160) ELSE '' END,
				entry.item->'traffic',
				CASE WHEN jsonb_typeof(entry.item->'signals') = 'array' THEN jsonb_array_length(entry.item->'signals') ELSE 0 END,
				ARRAY(
					SELECT rule.item->>'rule'
					FROM jsonb_array_elements(CASE WHEN jsonb_typeof(entry.item->'http_findings') = 'array'
						THEN entry.item->'http_findings' ELSE '[]'::jsonb END) AS rule(item)
					WHERE jsonb_typeof(rule.item->'rule') = 'string'
				)
			FROM jsonb_array_elements(records) WITH ORDINALITY AS entry(item, ordinal)
			CROSS JOIN LATERAL (
				SELECT COALESCE(entry.item->>'time', '') AS observed_at, COALESCE(entry.item->>'kind', '') AS kind
			) body
			WHERE jsonb_typeof(entry.item->'traffic') = 'object';

			UPDATE pavarotti_evidence_batches SET http_page_indexed = true WHERE expediente = case_name AND batch_key = key;
		$build$;

		CREATE FUNCTION pavarotti_index_http_page_insert() RETURNS TRIGGER
		LANGUAGE plpgsql AS $on_insert$
		BEGIN
			PERFORM pavarotti_store_http_page_batch(NEW.expediente, NEW.batch_key, NEW.payload);
			RETURN NEW;
		END;
		$on_insert$;
		CREATE TRIGGER pavarotti_index_http_page_insert
		AFTER INSERT ON pavarotti_evidence_batches
		FOR EACH ROW EXECUTE FUNCTION pavarotti_index_http_page_insert();
	`)
	return err
}

func (s *Store) prepareHTTPPageIndex(ctx context.Context) (bool, error) {
	const pendingQuery = `SELECT EXISTS (
		SELECT 1 FROM pavarotti_evidence_batches WHERE expediente = $1 AND NOT http_page_indexed)`
	const backfill = `
		SELECT pavarotti_store_http_page_batch(batch.expediente, batch.batch_key, batch.payload)
		FROM (
			SELECT expediente, batch_key, payload
			FROM pavarotti_evidence_batches
			WHERE expediente = $1 AND NOT http_page_indexed
			ORDER BY batch_key
			LIMIT $2
		) batch
	`
	return s.preparePageProjection(ctx, pendingQuery, backfill, maxHTTPBackfillBatches)
}

func (s *Store) postgresIndexedHTTPPage(ctx context.Context, request PageRequest, after pageCursor, limit int) ([]RecordRow, error) {
	result, err := s.db.QueryContext(ctx, `
		WITH page AS MATERIALIZED (
			SELECT batch_key, ordinal, id, stamp, kind, observed_at, title, source, source_id, traffic, signal_count
			FROM pavarotti_http_page
			WHERE expediente = $1
			  AND ($2 = '' OR (stamp, id) < ($3::text COLLATE "C", $2::text COLLATE "C"))
			  AND ($4::integer = 0 OR left(traffic->>'status', 1) = $4::integer::text)
			  AND ($5 = '' OR kind = $5)
			  AND ($6 = '' OR traffic->>'method' = $6)
			  AND ($7 = '' OR day >= $7)
			  AND ($8 = '' OR (length(day) >= 10 AND day <= $8))
			  AND ($9 = '' OR $9 = ANY(rules))
			ORDER BY stamp DESC, id DESC LIMIT $10
		)
		SELECT page.id, page.kind, page.observed_at,
			CASE WHEN edited.snapshot IS NULL THEN page.title ELSE left(COALESCE(edited.snapshot->>'title', ''), 240) END,
			CASE WHEN edited.snapshot IS NULL THEN page.source ELSE left(COALESCE(edited.snapshot->>'source', ''), 360) END,
			page.source_id, page.traffic, page.signal_count
		FROM page LEFT JOIN LATERAL (
			SELECT snapshot FROM pavarotti_note_revisions
			WHERE page.kind = 'nota' AND expediente = $1 AND batch_key = page.batch_key AND ordinal = page.ordinal
			ORDER BY revision DESC LIMIT 1
		) edited ON true
		ORDER BY page.stamp DESC, page.id DESC
	`, s.expediente, after.ID, after.Stamp, request.HTTPClass, request.HTTPSource, request.HTTPMethod,
		request.HTTPFrom, request.HTTPTo, request.HTTPRule, limit)
	if err != nil {
		return nil, err
	}
	return scanPostgresPage(result, limit)
}
