package caso

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var ErrMigrationConflict = errors.New("el destino tiene otra versión del mismo registro")

func (s *Store) ImportLocal(path string) (int, error) {
	if s.db == nil {
		return 0, errors.New("la migración requiere un destino PostgreSQL")
	}
	dir, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	if !dir.IsDir() {
		return 0, errors.New("el origen debe ser una carpeta de expediente")
	}
	source := &Store{path: path}
	unlock, err := source.lock()
	if err != nil {
		return 0, err
	}
	defer unlock()
	entries, err := os.ReadDir(path)
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var imported AuditDetails
	for _, entry := range entries {
		key, isJSON := strings.CutSuffix(entry.Name(), ".json")
		if !entry.Type().IsRegular() || !isJSON || !isBatchKey(key) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(path, entry.Name()))
		if err != nil {
			return 0, err
		}
		batch, err := decodeBatch(key, data)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", entry.Name(), err)
		}
		inserted, err := putLocalBatch(ctx, tx, s.expediente, key, data)
		if err != nil {
			return 0, err
		}
		if inserted {
			imported.Count += len(batch)
		}
		for index, record := range batch {
			if record.StaticReview() != nil {
				if err := source.walkLocalTriage(record, func(history []CodeDisposition) error {
					if err := lockCodeBatch(ctx, tx, s.expediente, key); err != nil {
						return err
					}
					for _, item := range history {
						added, err := putCodeTriage(ctx, tx, s.expediente, key, index+1, item)
						if err != nil {
							return err
						}
						if added {
							imported.TriageRevisions++
						}
					}
					return nil
				}); err != nil {
					return 0, err
				}
				continue
			}
			if record.Kind != "nota" {
				continue
			}
			edits, err := source.localEdits(record.ID)
			if err != nil {
				return 0, err
			}
			for offset, edited := range edits {
				if edited.ID != record.ID || edited.Kind != record.Kind || edited.Revision != offset+2 {
					return 0, fmt.Errorf("historial inválido para %s", record.ID)
				}
				added, err := putLocalEdit(ctx, tx, s.expediente, key, index+1, edited)
				if err != nil {
					return 0, err
				}
				if added {
					imported.NoteRevisions++
				}
			}
		}
	}
	if imported.Count+imported.NoteRevisions+imported.TriageRevisions > 0 {
		if err := s.appendAudit(ctx, tx, AuditImport, "", imported); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return imported.Count, nil
}

func putLocalBatch(ctx context.Context, tx *sql.Tx, expediente, key string, data []byte) (bool, error) {
	result, err := tx.ExecContext(ctx, `
		INSERT INTO pavarotti_evidence_batches (expediente, batch_key, payload)
		VALUES ($1, $2, $3) ON CONFLICT (expediente, batch_key) DO NOTHING`, expediente, key, data)
	if err != nil {
		return false, err
	}
	inserted, err := result.RowsAffected()
	if err != nil || inserted > 0 {
		return inserted > 0, err
	}
	var same bool
	if err := tx.QueryRowContext(ctx, `
		SELECT payload = $3::jsonb FROM pavarotti_evidence_batches
		WHERE expediente = $1 AND batch_key = $2`, expediente, key, data).Scan(&same); err != nil {
		return false, err
	}
	if !same {
		return false, fmt.Errorf("%s: %w", key, ErrMigrationConflict)
	}
	return false, nil
}

func putLocalEdit(ctx context.Context, tx *sql.Tx, expediente, key string, ordinal int, edited Record) (bool, error) {
	snapshot, err := json.Marshal(edited)
	if err != nil {
		return false, err
	}
	result, err := tx.ExecContext(ctx, `
		INSERT INTO pavarotti_note_revisions (expediente, batch_key, ordinal, revision, snapshot)
		VALUES ($1, $2, $3, $4, $5) ON CONFLICT (expediente, batch_key, ordinal, revision) DO NOTHING`,
		expediente, key, ordinal, edited.Revision, snapshot)
	if err != nil {
		return false, err
	}
	inserted, err := result.RowsAffected()
	if err != nil || inserted > 0 {
		return inserted > 0, err
	}
	var same bool
	if err := tx.QueryRowContext(ctx, `
		SELECT snapshot = $5::jsonb FROM pavarotti_note_revisions
		WHERE expediente = $1 AND batch_key = $2 AND ordinal = $3 AND revision = $4`,
		expediente, key, ordinal, edited.Revision, snapshot).Scan(&same); err != nil {
		return false, err
	}
	if !same {
		return false, fmt.Errorf("%s revisión %d: %w", edited.ID, edited.Revision, ErrMigrationConflict)
	}
	return false, nil
}
