package caso

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"time"
)

var (
	ErrRetentionCutoff   = errors.New("la fecha de retención debe ser anterior a la hora actual")
	ErrRetentionCoverage = errors.New("el respaldo debe pertenecer a este expediente y contener los eventos que vencerán")
	ErrRetentionChanged  = errors.New("la actividad cambió durante la verificación, vuelve a consultar la retención")
)

type AuditRetentionResult struct {
	Before       time.Time `json:"before"`
	Candidates   int64     `json:"candidates"`
	Removed      int64     `json:"removed"`
	BackupSHA256 string    `json:"backup_sha256,omitempty"`
}

type retentionEvent struct {
	Position   int64           `json:"position"`
	OccurredAt time.Time       `json:"occurred_at"`
	Actor      string          `json:"actor"`
	Source     string          `json:"source"`
	Action     string          `json:"action"`
	Target     string          `json:"target"`
	Details    json.RawMessage `json:"details"`
}

type retentionSelection struct {
	hash  hash.Hash
	count int64
}

func (selection *retentionSelection) add(data []byte) {
	_, _ = selection.hash.Write(data)
	_, _ = selection.hash.Write([]byte{'\n'})
	selection.count++
}

func (s *Store) auditRetentionCutoff(before time.Time) error {
	if !s.HasAuditLog() {
		return ErrAuditUnavailable
	}
	if before.IsZero() || !before.Before(time.Now()) {
		return ErrRetentionCutoff
	}
	return nil
}

func (s *Store) PreviewAuditRetention(ctx context.Context, before time.Time) (AuditRetentionResult, error) {
	if err := s.auditRetentionCutoff(before); err != nil {
		return AuditRetentionResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	result := AuditRetentionResult{Before: before.UTC()}
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM pavarotti_audit_events
		WHERE expediente = $1 AND occurred_at < $2`, s.expediente, result.Before).Scan(&result.Candidates)
	return result, err
}

func (s *Store) ApplyAuditRetention(ctx context.Context, before time.Time, archive io.Reader) (AuditRetentionResult, error) {
	if err := s.auditRetentionCutoff(before); err != nil {
		return AuditRetentionResult{}, err
	}
	if archive == nil {
		return AuditRetentionResult{}, ErrRetentionCoverage
	}
	result := AuditRetentionResult{Before: before.UTC()}
	verified, summary, err := s.verifyRetentionArchive(ctx, result.Before, archive)
	if err != nil {
		return AuditRetentionResult{}, err
	}
	result.Candidates, result.BackupSHA256 = verified.count, summary.SHA256
	tx, err := s.beginCaseWrite(ctx, true)
	if err != nil {
		return AuditRetentionResult{}, err
	}
	defer tx.Rollback()
	current, err := s.retentionSelection(ctx, tx, result.Before)
	if err != nil {
		return AuditRetentionResult{}, err
	}
	if verified.count != current.count || !bytes.Equal(verified.hash.Sum(nil), current.hash.Sum(nil)) {
		return AuditRetentionResult{}, ErrRetentionChanged
	}
	if result.Candidates == 0 {
		return result, nil
	}
	deleted, err := tx.ExecContext(ctx, `DELETE FROM pavarotti_audit_events
		WHERE expediente = $1 AND occurred_at < $2`, s.expediente, result.Before)
	if err != nil {
		return AuditRetentionResult{}, err
	}
	result.Removed, err = deleted.RowsAffected()
	if err != nil {
		return AuditRetentionResult{}, err
	}
	if result.Removed != result.Candidates {
		return AuditRetentionResult{}, ErrRetentionChanged
	}
	if err := s.appendAudit(ctx, tx, AuditRetention, "", AuditDetails{RemovedEvents: result.Removed,
		RetentionBefore: result.Before.Format(time.RFC3339Nano), BackupSHA256: summary.SHA256}); err != nil {
		return AuditRetentionResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return AuditRetentionResult{}, err
	}
	return result, nil
}

func (s *Store) verifyRetentionArchive(ctx context.Context, before time.Time, archive io.Reader) (retentionSelection, BackupSummary, error) {
	selection := retentionSelection{hash: sha256.New()}
	reader, err := openBackup(ctx, archive)
	if err != nil {
		return selection, BackupSummary{}, err
	}
	if reader.manifest.SourceCase != s.expediente {
		return selection, BackupSummary{}, ErrRetentionCoverage
	}
	rows, err := s.retentionRows(ctx, s.db, before)
	if err != nil {
		return selection, BackupSummary{}, err
	}
	defer rows.Close()
	current, err := nextRetentionEvent(rows)
	if err != nil {
		return selection, BackupSummary{}, err
	}
	summary, err := reader.readRows(ctx, func(table caseBackupTable, data json.RawMessage) error {
		if table.kind != "audit_event" || current.Position == 0 {
			return nil
		}
		var stored retentionEvent
		if err := json.Unmarshal(data, &stored); err != nil || stored.Position < 1 || stored.OccurredAt.IsZero() {
			return ErrBackupIntegrity
		}
		if stored.Position < current.Position {
			return nil
		}
		stored.OccurredAt = stored.OccurredAt.UTC()
		fromArchive, err := json.Marshal(stored)
		if err != nil {
			return ErrBackupIntegrity
		}
		wanted, err := json.Marshal(current)
		if err != nil {
			return err
		}
		if !bytes.Equal(fromArchive, wanted) {
			return ErrRetentionCoverage
		}
		selection.add(wanted)
		current, err = nextRetentionEvent(rows)
		return err
	})
	if err == nil && current.Position != 0 {
		err = ErrRetentionCoverage
	}
	return selection, summary, err
}

func (s *Store) retentionSelection(ctx context.Context, query queryer, before time.Time) (retentionSelection, error) {
	selection := retentionSelection{hash: sha256.New()}
	rows, err := s.retentionRows(ctx, query, before)
	if err != nil {
		return selection, err
	}
	defer rows.Close()
	for {
		event, err := nextRetentionEvent(rows)
		if err != nil || event.Position == 0 {
			return selection, err
		}
		data, err := json.Marshal(event)
		if err != nil {
			return selection, err
		}
		selection.add(data)
	}
}

func (s *Store) retentionRows(ctx context.Context, query queryer, before time.Time) (*sql.Rows, error) {
	return query.QueryContext(ctx, `SELECT position, occurred_at, actor, source, action, target, details
		FROM pavarotti_audit_events WHERE expediente = $1 AND occurred_at < $2 ORDER BY position`, s.expediente, before)
}

func nextRetentionEvent(rows *sql.Rows) (retentionEvent, error) {
	var event retentionEvent
	if !rows.Next() {
		return event, rows.Err()
	}
	var details []byte
	err := rows.Scan(&event.Position, &event.OccurredAt, &event.Actor, &event.Source, &event.Action, &event.Target, &details)
	event.Details = details
	event.OccurredAt = event.OccurredAt.UTC()
	return event, err
}
