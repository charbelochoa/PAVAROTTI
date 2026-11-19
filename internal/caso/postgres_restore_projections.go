package caso

import (
	"context"
	"database/sql"
)

func migrateDeferredProjections(ctx context.Context, tx *sql.Tx) error {
	var installed bool
	if err := tx.QueryRowContext(ctx, `SELECT to_regprocedure('pavarotti_defer_page_projections(text)') IS NOT NULL`).Scan(&installed); err != nil || installed {
		return err
	}
	_, err := tx.ExecContext(ctx, `
		CREATE FUNCTION pavarotti_defer_page_projections(case_name TEXT) RETURNS BOOLEAN
		LANGUAGE sql STABLE AS $defer$
			SELECT current_setting('pavarotti.restoring_case', true) IS NOT DISTINCT FROM case_name;
		$defer$;

		CREATE OR REPLACE FUNCTION pavarotti_index_http_page_insert() RETURNS TRIGGER
		LANGUAGE plpgsql AS $on_insert$
		BEGIN
			IF NOT pavarotti_defer_page_projections(NEW.expediente) THEN
				PERFORM pavarotti_store_http_page_batch(NEW.expediente, NEW.batch_key, NEW.payload);
			END IF;
			RETURN NEW;
		END;
		$on_insert$;

		CREATE OR REPLACE FUNCTION pavarotti_search_batch_insert() RETURNS TRIGGER LANGUAGE plpgsql AS $on_batch$
		BEGIN
			IF NOT pavarotti_defer_page_projections(NEW.expediente) AND jsonb_array_length(NEW.payload) <= 1000 THEN
				PERFORM pavarotti_store_search_batch(NEW.expediente, NEW.batch_key, NEW.payload, 1);
			END IF;
			RETURN NEW;
		END;
		$on_batch$;
	`)
	return err
}
