package caso

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

func migrateCodeTriage(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS pavarotti_code_triage (
			expediente TEXT NOT NULL,
			batch_key TEXT NOT NULL,
			ordinal BIGINT NOT NULL CHECK (ordinal > 0),
			finding_key TEXT NOT NULL,
			revision BIGINT NOT NULL CHECK (revision > 0),
			entry JSONB NOT NULL CHECK (jsonb_typeof(entry) = 'object'),
			PRIMARY KEY (expediente, batch_key, ordinal, finding_key, revision),
			FOREIGN KEY (expediente, batch_key) REFERENCES pavarotti_evidence_batches (expediente, batch_key) ON DELETE CASCADE
		)`)
	return err
}

func readCodeTriage(ctx context.Context, query queryer, statement string, args ...any) ([]CodeDisposition, error) {
	rows, err := query.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]CodeDisposition, 0)
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var item CodeDisposition
		if err := json.Unmarshal(data, &item); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func lockCodeBatch(ctx context.Context, tx *sql.Tx, expediente, batch string) error {
	var present int
	err := tx.QueryRowContext(ctx, `SELECT 1 FROM pavarotti_evidence_batches
		WHERE expediente = $1 AND batch_key = $2 FOR UPDATE`, expediente, batch).Scan(&present)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func (s *Store) classifyCodePostgres(ctx context.Context, batch string, ordinal int, next CodeDisposition) (CodeDisposition, error) {
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return CodeDisposition{}, err
	}
	defer tx.Rollback()
	if err := lockCodeBatch(ctx, tx, s.expediente, batch); err != nil {
		return CodeDisposition{}, err
	}
	key := next.FindingKey.hash()
	var current int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(revision), 0) FROM pavarotti_code_triage
		WHERE expediente = $1 AND batch_key = $2 AND ordinal = $3 AND finding_key = $4`,
		s.expediente, batch, ordinal, key).Scan(&current); err != nil {
		return CodeDisposition{}, err
	}
	if current != next.Revision-1 {
		return CodeDisposition{}, ErrRevisionConflict
	}
	next.Time = Now()
	if err := putCodeTriage(ctx, tx, s.expediente, batch, ordinal, next); err != nil {
		return CodeDisposition{}, err
	}
	if err := s.appendAudit(ctx, tx, AuditTriage, fmt.Sprintf("%s-%d", batch, ordinal), AuditDetails{
		Revision: next.Revision, Finding: &next.FindingKey, Status: next.Status,
	}); err != nil {
		return CodeDisposition{}, err
	}
	if err := tx.Commit(); err != nil {
		return CodeDisposition{}, err
	}
	return next, nil
}

func putCodeTriage(ctx context.Context, tx *sql.Tx, expediente, batch string, ordinal int, item CodeDisposition) error {
	data, err := json.Marshal(item)
	if err != nil {
		return err
	}
	key := item.FindingKey.hash()
	result, err := tx.ExecContext(ctx, `INSERT INTO pavarotti_code_triage
		(expediente, batch_key, ordinal, finding_key, revision, entry) VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT DO NOTHING`, expediente, batch, ordinal, key, item.Revision, data)
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil || inserted > 0 {
		return err
	}
	var same bool
	if err := tx.QueryRowContext(ctx, `SELECT entry = $6::jsonb FROM pavarotti_code_triage
		WHERE expediente = $1 AND batch_key = $2 AND ordinal = $3 AND finding_key = $4 AND revision = $5`,
		expediente, batch, ordinal, key, item.Revision, data).Scan(&same); err != nil {
		return err
	}
	if !same {
		return fmt.Errorf("clasificación %d de %s-%d: %w", item.Revision, batch, ordinal, ErrMigrationConflict)
	}
	return nil
}
