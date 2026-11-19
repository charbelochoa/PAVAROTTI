package caso

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

const migrationLock int64 = 6953370548850278928

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
	return tx.Commit()
}

func (s *Store) postgresRecords() ([]Record, error) {
	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `
		SELECT batch_key, payload FROM pavarotti_evidence_batches
		WHERE expediente = $1 ORDER BY batch_key`, s.expediente)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := make([]Record, 0)
	for rows.Next() {
		var key string
		var data []byte
		if err := rows.Scan(&key, &data); err != nil {
			return nil, err
		}
		batch, err := decodeBatch(key, data)
		if err != nil {
			return nil, err
		}
		records = append(records, batch...)
	}
	return records, rows.Err()
}
