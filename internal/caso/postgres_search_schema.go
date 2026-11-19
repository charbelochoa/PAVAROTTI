package caso

import (
	"context"
	"database/sql"
)

func migrateSearchPage(ctx context.Context, tx *sql.Tx) error {
	var installed bool
	if err := tx.QueryRowContext(ctx, `SELECT to_regclass('pavarotti_search_page') IS NOT NULL`).Scan(&installed); err != nil || installed {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		ALTER TABLE pavarotti_evidence_batches ADD COLUMN search_page_indexed BOOLEAN NOT NULL DEFAULT false;
		ALTER TABLE pavarotti_evidence_batches ADD COLUMN search_page_position BIGINT NOT NULL DEFAULT 1;
		CREATE INDEX pavarotti_search_page_pending
		ON pavarotti_evidence_batches (expediente, batch_key) WHERE NOT search_page_indexed;

		CREATE TABLE pavarotti_search_page (
			expediente TEXT NOT NULL,
			batch_key TEXT NOT NULL,
			ordinal BIGINT NOT NULL,
			revision BIGINT NOT NULL,
			id TEXT COLLATE "C" NOT NULL,
			stamp TEXT COLLATE "C" NOT NULL,
			observed_at TEXT NOT NULL,
			kind TEXT NOT NULL,
			title TEXT NOT NULL,
			source TEXT NOT NULL,
			source_id TEXT NOT NULL,
			traffic JSONB,
			signal_count INTEGER NOT NULL,
			rules TEXT[] NOT NULL,
			document TEXT COLLATE "C" NOT NULL,
			partial BOOLEAN NOT NULL,
			PRIMARY KEY (expediente, batch_key, ordinal),
			FOREIGN KEY (expediente, batch_key)
				REFERENCES pavarotti_evidence_batches (expediente, batch_key) ON DELETE CASCADE
		);
		CREATE INDEX pavarotti_search_page_order ON pavarotti_search_page (expediente, stamp DESC, id DESC);
		CREATE INDEX pavarotti_search_page_partial ON pavarotti_search_page (expediente) WHERE partial;

		CREATE FUNCTION pavarotti_search_document(record_id TEXT, record_kind TEXT, recorded_at TEXT, body JSONB)
		RETURNS TEXT LANGUAGE SQL IMMUTABLE AS $document$
			SELECT concat_ws(chr(31),
				translate(lower(concat_ws(chr(31), record_id, record_kind, recorded_at,
					body->>'title', body->>'source', body->>'source_id', body->>'sha256', body->>'details',
					body->>'signals', body->'traffic'->>'method', body->'traffic'->>'type', body->'traffic'->>'status',
					body->'traffic'->>'millis', body->'traffic'->>'bucket')), 'ÁÉÍÓÚÜÑ', 'áéíóúüñ'),
				CASE WHEN jsonb_typeof(body->'dependencies'->'entries') = 'array' THEN
				(SELECT string_agg(lower(field.value), chr(31))
				 FROM jsonb_array_elements(body->'dependencies'->'entries') AS dependency(item)
				 CROSS JOIN LATERAL (VALUES (dependency.item->>'name'), (dependency.item->>'version'),
					(dependency.item->>'installed_as'), (dependency.item->'replacement'->>'name'),
					(dependency.item->'replacement'->>'version')) AS field(value))
				END
			);
		$document$;

		CREATE FUNCTION pavarotti_store_search_rows(case_name TEXT, batch_name TEXT, records JSONB, first_ordinal BIGINT, fixed_revision BIGINT)
		RETURNS VOID LANGUAGE SQL AS $build$
			WITH entries AS (
				SELECT first_ordinal + entry.ordinal - 1 AS position, entry.item AS original
				FROM jsonb_array_elements(records) WITH ORDINALITY AS entry(item, ordinal)
			), current_rows AS (
				SELECT entry.position, batch_name || '-' || entry.position::text AS id,
					COALESCE(entry.original->>'time', '') AS observed_at, COALESCE(entry.original->>'kind', '') AS kind,
					COALESCE(edited.snapshot, entry.original) AS body, COALESCE(NULLIF(fixed_revision, 0), edited.revision, 1) AS revision
				FROM entries AS entry
				LEFT JOIN LATERAL (
					SELECT revision, snapshot FROM pavarotti_note_revisions
					WHERE fixed_revision = 0 AND entry.original->>'kind' = 'nota'
					  AND expediente = case_name AND batch_key = batch_name AND ordinal = entry.position
					ORDER BY revision DESC LIMIT 1
				) edited ON true
			), documents AS MATERIALIZED (
				SELECT current_rows.*, pavarotti_search_document(id, kind, observed_at, body) AS document
				FROM current_rows
			)
			INSERT INTO pavarotti_search_page(
				expediente, batch_key, ordinal, revision, id, stamp, observed_at, kind, title, source,
				source_id, traffic, signal_count, rules, document, partial)
			SELECT case_name, batch_name, position, revision, id,
				CASE WHEN right(observed_at, 1) = 'Z' THEN left(observed_at, -1) ELSE observed_at END,
				observed_at, kind, left(COALESCE(body->>'title', ''), 240), left(COALESCE(body->>'source', ''), 360),
				CASE WHEN kind = 'binario' THEN left(COALESCE(body->>'source_id', ''), 160) ELSE '' END,
				CASE WHEN jsonb_typeof(body->'traffic') = 'object' THEN body->'traffic' END,
				CASE WHEN jsonb_typeof(body->'signals') = 'array' THEN jsonb_array_length(body->'signals') ELSE 0 END,
				ARRAY(
					SELECT rule.item->>'rule'
					FROM jsonb_array_elements(CASE WHEN jsonb_typeof(body->'http_findings') = 'array'
						THEN body->'http_findings' ELSE '[]'::jsonb END) AS rule(item)
					WHERE jsonb_typeof(rule.item->'rule') = 'string'
				), left(document, 16384), length(document) > 16384
			FROM documents
			ON CONFLICT (expediente, batch_key, ordinal) DO UPDATE SET
				revision = EXCLUDED.revision, title = EXCLUDED.title, source = EXCLUDED.source,
				source_id = EXCLUDED.source_id, traffic = EXCLUDED.traffic, signal_count = EXCLUDED.signal_count,
				rules = EXCLUDED.rules, document = EXCLUDED.document, partial = EXCLUDED.partial
			WHERE pavarotti_search_page.revision <= EXCLUDED.revision;
		$build$;

		CREATE FUNCTION pavarotti_store_search_batch(case_name TEXT, batch_name TEXT, records JSONB, start_at BIGINT) RETURNS VOID
		LANGUAGE plpgsql AS $batch$
		DECLARE
			part JSONB;
			next_position BIGINT;
		BEGIN
			part := jsonb_path_query_array(records, '$[$first to $last]',
				jsonb_build_object('first', start_at - 1, 'last', start_at + 998));
			PERFORM pavarotti_store_search_rows(case_name, batch_name, part, start_at, 0);
			next_position := start_at + jsonb_array_length(part);
			UPDATE pavarotti_evidence_batches
			SET search_page_indexed = next_position > jsonb_array_length(records), search_page_position = next_position
			WHERE expediente = case_name AND batch_key = batch_name;
		END;
		$batch$;

		CREATE FUNCTION pavarotti_search_batch_insert() RETURNS TRIGGER LANGUAGE plpgsql AS $on_batch$
		BEGIN
			IF jsonb_array_length(NEW.payload) <= 1000 THEN
				PERFORM pavarotti_store_search_batch(NEW.expediente, NEW.batch_key, NEW.payload, 1);
			END IF;
			RETURN NEW;
		END;
		$on_batch$;
		CREATE TRIGGER pavarotti_search_batch_insert AFTER INSERT ON pavarotti_evidence_batches
		FOR EACH ROW EXECUTE FUNCTION pavarotti_search_batch_insert();

		CREATE FUNCTION pavarotti_search_note_insert() RETURNS TRIGGER LANGUAGE plpgsql AS $on_note$
		BEGIN
			IF EXISTS (SELECT 1 FROM pavarotti_evidence_batches
				WHERE expediente = NEW.expediente AND batch_key = NEW.batch_key AND NEW.ordinal < search_page_position) THEN
				PERFORM pavarotti_store_search_rows(NEW.expediente, NEW.batch_key, jsonb_build_array(NEW.snapshot), NEW.ordinal, NEW.revision);
			END IF;
			RETURN NEW;
		END;
		$on_note$;
		CREATE TRIGGER pavarotti_search_note_insert AFTER INSERT ON pavarotti_note_revisions
		FOR EACH ROW EXECUTE FUNCTION pavarotti_search_note_insert();
	`); err != nil {
		return err
	}

	_, err := tx.ExecContext(ctx, `
		DO $optional$
		DECLARE extension_schema name;
		BEGIN
			IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'pg_trgm') THEN
				BEGIN
					CREATE EXTENSION IF NOT EXISTS pg_trgm;
				EXCEPTION WHEN insufficient_privilege OR feature_not_supported OR undefined_file THEN
					NULL;
				END;
			END IF;
			SELECT namespace.nspname INTO extension_schema
			FROM pg_extension AS extension JOIN pg_namespace AS namespace ON namespace.oid = extension.extnamespace
			WHERE extension.extname = 'pg_trgm';
			IF extension_schema IS NOT NULL THEN
				BEGIN
					EXECUTE format('CREATE INDEX pavarotti_search_page_trigrams ON pavarotti_search_page USING gin (document %I.gin_trgm_ops)', extension_schema);
				EXCEPTION WHEN insufficient_privilege OR undefined_object THEN
					NULL;
				END;
			END IF;
		END;
		$optional$;
	`)
	return err
}
