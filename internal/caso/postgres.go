package caso

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

const migrationLock int64 = 6953370548850278928
const caseWriteLockSeed int64 = 2781632215710108871

func OpenPostgres(ctx context.Context, dsn, expediente string) (*Store, error) {
	expediente = strings.TrimSpace(expediente)
	if expediente == "" || len(expediente) > 120 {
		return nil, errors.New("el expediente de PostgreSQL debe tener entre 1 y 120 bytes")
	}
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("se requiere una cadena de conexión de PostgreSQL")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("cadena de conexión de PostgreSQL inválida")
	}
	db := stdlib.OpenDB(*config)
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(2)
	db.SetConnMaxIdleTime(5 * time.Minute)
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if err := migrate(ctx, db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("no se pudo abrir el expediente en PostgreSQL: %w", err)
	}
	return &Store{db: db, expediente: expediente}, nil
}

func migrate(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, migrationLock); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS pavarotti_evidence_batches (
			expediente TEXT NOT NULL,
			batch_key TEXT NOT NULL,
			payload JSONB NOT NULL CHECK (jsonb_typeof(payload) = 'array'),
			PRIMARY KEY (expediente, batch_key)
		)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS pavarotti_note_revisions (
			expediente TEXT NOT NULL,
			batch_key TEXT NOT NULL,
			ordinal BIGINT NOT NULL CHECK (ordinal > 0),
			revision BIGINT NOT NULL CHECK (revision >= 2),
			snapshot JSONB NOT NULL CHECK (jsonb_typeof(snapshot) = 'object'),
			PRIMARY KEY (expediente, batch_key, ordinal, revision),
			FOREIGN KEY (expediente, batch_key)
				REFERENCES pavarotti_evidence_batches (expediente, batch_key)
		)`); err != nil {
		return err
	}
	if err := migrateAnalysisQueue(ctx, tx); err != nil {
		return err
	}
	if err := migrateCodeTriage(ctx, tx); err != nil {
		return err
	}
	if err := migrateSharedAccess(ctx, tx); err != nil {
		return err
	}
	if err := migrateAudit(ctx, tx); err != nil {
		return err
	}
	if err := migrateHTTPPageIndex(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) beginCaseWrite(ctx context.Context, exclusive bool) (*sql.Tx, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	lock := `SELECT pg_advisory_xact_lock_shared(hashtextextended($1, $2))`
	if exclusive {
		lock = `SELECT pg_advisory_xact_lock(hashtextextended($1, $2))`
	}
	if _, err := tx.ExecContext(ctx, lock, s.expediente, caseWriteLockSeed); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func (s *Store) postgresWalk(ctx context.Context, visit func(Record) error) error {
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `
		SELECT b.batch_key, b.payload, COALESCE((
			SELECT jsonb_agg(latest.snapshot)
			FROM (
				SELECT DISTINCT ON (r.ordinal) r.snapshot
				FROM pavarotti_note_revisions r
				WHERE r.expediente = b.expediente AND r.batch_key = b.batch_key
				ORDER BY r.ordinal, r.revision DESC
			) latest
		), '[]'::jsonb)
		FROM pavarotti_evidence_batches b
		WHERE b.expediente = $1 ORDER BY b.batch_key`, s.expediente)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		var data, overlays []byte
		if err := rows.Scan(&key, &data, &overlays); err != nil {
			return err
		}
		batch, err := decodeBatch(key, data)
		if err != nil {
			return err
		}
		var edited []Record
		if err := json.Unmarshal(overlays, &edited); err != nil {
			return err
		}
		for _, record := range edited {
			_, ordinal, valid := recordPosition(record.ID)
			if valid && ordinal <= len(batch) && batch[ordinal-1].ID == record.ID {
				batch[ordinal-1] = record
			}
		}
		for _, record := range batch {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := visit(record); err != nil {
				return err
			}
		}
	}
	return rows.Err()
}
