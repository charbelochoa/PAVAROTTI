package caso

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var (
	ErrNotFound         = errors.New("registro inexistente")
	ErrRevisionConflict = errors.New("la revisión cambió, actualiza el expediente antes de guardar")
	ErrReadOnly         = errors.New("solo se pueden editar notas del analista")
	ErrInvalidEdit      = errors.New("la nota requiere un título de hasta 160 bytes, una referencia de hasta 512 bytes y texto de hasta 8000 bytes")
)

func (s *Store) Edit(id string, revision int, title, source, details string) (Record, error) {
	return s.EditContext(context.Background(), id, revision, title, source, details)
}

func (s *Store) EditContext(ctx context.Context, id string, revision int, title, source, details string) (Record, error) {
	key, ordinal, valid := recordPosition(id)
	if !valid {
		return Record{}, ErrNotFound
	}
	title, source, details = strings.TrimSpace(title), strings.TrimSpace(source), strings.TrimSpace(details)
	if title == "" || details == "" || len(title) > 160 || len(source) > 512 || len(details) > 8000 {
		return Record{}, ErrInvalidEdit
	}
	rewrite := func(original, current Record) (Record, error) {
		if original.Kind != "nota" {
			return Record{}, ErrReadOnly
		}
		if current.Revision != revision {
			return Record{}, ErrRevisionConflict
		}
		current.Title, current.Source, current.Details = title, source, details
		current.Revision++
		current.UpdatedAt = Now()
		return current, nil
	}
	if s.db != nil {
		return s.postgresEdit(ctx, key, ordinal, rewrite)
	}
	unlock, err := s.lockContext(ctx)
	if err != nil {
		return Record{}, err
	}
	defer unlock()
	original, err := s.localRecord(key, ordinal)
	if err != nil {
		return Record{}, err
	}
	edits, err := s.localEdits(id)
	if err != nil {
		return Record{}, err
	}
	latest := original
	if len(edits) > 0 {
		latest = edits[len(edits)-1]
	}
	current, err := rewrite(original, latest)
	if err != nil {
		return Record{}, err
	}
	content, err := json.Marshal(append(edits, current))
	if err != nil {
		return Record{}, err
	}
	destination := s.editPath(id)
	if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
		return Record{}, err
	}
	if err := atomicWrite(destination, content); err != nil {
		return Record{}, err
	}
	return current, nil
}

func (s *Store) History(id string) ([]Record, error) {
	key, ordinal, valid := recordPosition(id)
	if !valid {
		return nil, ErrNotFound
	}
	var original Record
	var edits []Record
	var err error
	if s.db != nil {
		original, edits, err = s.postgresHistory(key, ordinal)
	} else {
		unlock, lockErr := s.lock()
		if lockErr != nil {
			return nil, lockErr
		}
		defer unlock()
		original, err = s.localRecord(key, ordinal)
		if err == nil {
			edits, err = s.localEdits(id)
		}
	}
	if err != nil {
		return nil, err
	}
	if len(edits) == 0 {
		return []Record{}, nil
	}
	return append([]Record{original}, edits[:len(edits)-1]...), nil
}

func (s *Store) localRecord(key string, ordinal int) (Record, error) {
	data, err := os.ReadFile(filepath.Join(s.path, key+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, err
	}
	return batchRecord(key, ordinal, data)
}

func (s *Store) localEdits(id string) ([]Record, error) {
	data, err := os.ReadFile(s.editPath(id))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var edits []Record
	err = json.Unmarshal(data, &edits)
	return edits, err
}

func (s *Store) editPath(id string) string {
	return filepath.Join(s.path, ".ediciones", id+".json")
}

func recordPosition(id string) (string, int, bool) {
	key, number, found := strings.Cut(id, "-")
	ordinal, err := strconv.Atoi(number)
	return key, ordinal, found && err == nil && isBatchKey(key) && ordinal > 0 && strconv.Itoa(ordinal) == number
}

func batchRecord(key string, ordinal int, data []byte) (Record, error) {
	batch, err := decodeBatch(key, data)
	if err != nil {
		return Record{}, err
	}
	if ordinal > len(batch) {
		return Record{}, ErrNotFound
	}
	return batch[ordinal-1], nil
}

func (s *Store) postgresEdit(ctx context.Context, key string, ordinal int, rewrite func(Record, Record) (Record, error)) (Record, error) {
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	tx, err := s.beginCaseWrite(ctx, false)
	if err != nil {
		return Record{}, err
	}
	defer tx.Rollback()
	var payload []byte
	err = tx.QueryRowContext(ctx, `
		SELECT payload FROM pavarotti_evidence_batches
		WHERE expediente = $1 AND batch_key = $2 FOR UPDATE`, s.expediente, key).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, err
	}
	original, err := batchRecord(key, ordinal, payload)
	if err != nil {
		return Record{}, err
	}
	var snapshot []byte
	var latest Record
	err = tx.QueryRowContext(ctx, `
		SELECT snapshot FROM pavarotti_note_revisions
		WHERE expediente = $1 AND batch_key = $2 AND ordinal = $3
		ORDER BY revision DESC LIMIT 1`, s.expediente, key, ordinal).Scan(&snapshot)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		latest = original
	case err != nil:
		return Record{}, err
	default:
		if err := json.Unmarshal(snapshot, &latest); err != nil {
			return Record{}, err
		}
	}
	current, err := rewrite(original, latest)
	if err != nil {
		return Record{}, err
	}
	snapshot, err = json.Marshal(current)
	if err != nil {
		return Record{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO pavarotti_note_revisions (expediente, batch_key, ordinal, revision, snapshot)
		VALUES ($1, $2, $3, $4, $5)`, s.expediente, key, ordinal, current.Revision, snapshot); err != nil {
		return Record{}, err
	}
	if err := s.appendAudit(ctx, tx, AuditEdit, current.ID, AuditDetails{Revision: current.Revision}); err != nil {
		return Record{}, err
	}
	return current, tx.Commit()
}

func (s *Store) postgresHistory(key string, ordinal int) (Record, []Record, error) {
	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	defer cancel()
	var payload []byte
	row := s.db.QueryRowContext(ctx, `
		SELECT payload FROM pavarotti_evidence_batches
		WHERE expediente = $1 AND batch_key = $2`, s.expediente, key)
	if err := row.Scan(&payload); errors.Is(err, sql.ErrNoRows) {
		return Record{}, nil, ErrNotFound
	} else if err != nil {
		return Record{}, nil, err
	}
	original, err := batchRecord(key, ordinal, payload)
	if err != nil {
		return Record{}, nil, err
	}
	edits, err := postgresEdits(ctx, s.db, s.expediente, key, ordinal)
	return original, edits, err
}

type queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func postgresEdits(ctx context.Context, query queryer, expediente, key string, ordinal int) ([]Record, error) {
	rows, err := query.QueryContext(ctx, `
		SELECT snapshot FROM pavarotti_note_revisions
		WHERE expediente = $1 AND batch_key = $2 AND ordinal = $3 ORDER BY revision`, expediente, key, ordinal)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var edits []Record
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var record Record
		if err := json.Unmarshal(data, &record); err != nil {
			return nil, err
		}
		edits = append(edits, record)
	}
	return edits, rows.Err()
}
