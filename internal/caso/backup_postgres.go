package caso

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

type caseBackupTable struct {
	kind    string
	table   string
	columns string
	order   string
	restore string
}

var caseBackupTables = []caseBackupTable{
	{kind: "batch", table: "pavarotti_evidence_batches", columns: "batch_key, payload", order: "batch_key"},
	{kind: "note_revision", table: "pavarotti_note_revisions", columns: "batch_key, ordinal, revision, snapshot", order: "batch_key, ordinal, revision"},
	{kind: "triage_revision", table: "pavarotti_code_triage", columns: "batch_key, ordinal, finding_key, revision, entry", order: "batch_key, ordinal, finding_key, revision"},
	{kind: "job", table: "pavarotti_analysis_jobs", columns: jobFields + ", snapshot, result", order: "id",
		restore: `id, fingerprint, agent_version,
			CASE WHEN state = 'running' THEN CASE WHEN attempts >= 3 THEN 'failed' ELSE 'queued' END ELSE state END,
			priority, attempts, created_at, CASE WHEN state = 'running' THEN clock_timestamp() ELSE updated_at END,
			CASE WHEN state = 'running' AND attempts >= 3 THEN 'Se agotaron los intentos antes de restaurar el expediente' ELSE failure END,
			snapshot, result`},
	{kind: "audit_head", table: "pavarotti_audit_heads", columns: "position", order: "position"},
	{kind: "audit_event", table: "pavarotti_audit_events", columns: "position, occurred_at, actor, source, action, target, details", order: "position"},
}

func (table caseBackupTable) export(ctx context.Context, tx *sql.Tx, caseName string, writer io.Writer) (int, error) {
	rows, err := tx.QueryContext(ctx, `SELECT to_jsonb(item) FROM (SELECT `+table.columns+
		` FROM `+table.table+` WHERE expediente = $1 ORDER BY `+table.order+`) AS item`, caseName)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return 0, err
		}
		if err := writeBackupFrame(writer, table.kind, data); err != nil {
			return 0, err
		}
		count++
	}
	return count, rows.Err()
}

func (table caseBackupTable) insert(ctx context.Context, tx *sql.Tx, caseName string, data json.RawMessage) error {
	projection := table.columns
	if table.restore != "" {
		projection = table.restore
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO `+table.table+` (expediente, `+table.columns+
		`) SELECT $1, `+projection+` FROM jsonb_populate_record(NULL::`+table.table+`, $2::jsonb) AS item`, caseName, []byte(data))
	if err == nil {
		return nil
	}
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) && (strings.HasPrefix(databaseError.Code, "22") || strings.HasPrefix(databaseError.Code, "23")) {
		return fmt.Errorf("%w: fila %s (%s)", ErrBackupIntegrity, table.kind, databaseError.Code)
	}
	return err
}

func (s *Store) RestoreCase(ctx context.Context, source io.Reader) (BackupSummary, error) {
	if s.db == nil {
		return BackupSummary{}, ErrBackupUnavailable
	}
	reader, err := openBackup(ctx, source)
	if err != nil {
		return BackupSummary{}, err
	}
	tx, err := s.beginCaseWrite(ctx, true)
	if err != nil {
		return BackupSummary{}, err
	}
	defer tx.Rollback()
	var occupied bool
	if err := tx.QueryRowContext(ctx, `SELECT
		EXISTS (SELECT 1 FROM pavarotti_evidence_batches WHERE expediente = $1) OR
		EXISTS (SELECT 1 FROM pavarotti_analysis_jobs WHERE expediente = $1) OR
		EXISTS (SELECT 1 FROM pavarotti_audit_heads WHERE expediente = $1)`, s.expediente).Scan(&occupied); err != nil {
		return BackupSummary{}, err
	}
	if occupied {
		return BackupSummary{}, ErrBackupDestination
	}
	summary, err := reader.readRows(ctx, func(table caseBackupTable, data json.RawMessage) error {
		return table.insert(ctx, tx, s.expediente, data)
	})
	if err != nil {
		return BackupSummary{}, err
	}
	if err := s.checkRestoredReferences(ctx, tx); err != nil {
		return BackupSummary{}, err
	}
	if err := s.appendAudit(ctx, tx, AuditRestore, "", AuditDetails{BackupSHA256: summary.SHA256}); err != nil {
		return BackupSummary{}, err
	}
	if err := tx.Commit(); err != nil {
		return BackupSummary{}, err
	}
	return summary, nil
}

func (s *Store) checkRestoredReferences(ctx context.Context, tx *sql.Tx) error {
	var valid bool
	err := tx.QueryRowContext(ctx, `SELECT NOT EXISTS (
		SELECT 1 FROM pavarotti_evidence_batches b WHERE b.expediente = $1 AND (
			b.batch_key !~ '^[a-f0-9]{64}$' OR EXISTS (
				SELECT 1 FROM jsonb_array_elements(b.payload) AS item WHERE jsonb_typeof(item) <> 'object'))
	) AND NOT EXISTS (
		SELECT 1 FROM pavarotti_note_revisions r JOIN pavarotti_evidence_batches b USING (expediente, batch_key)
		WHERE r.expediente = $1 AND (r.ordinal > jsonb_array_length(b.payload)
			OR (b.payload->(CASE WHEN r.ordinal <= jsonb_array_length(b.payload) THEN (r.ordinal-1)::int END)->>'kind') IS DISTINCT FROM 'nota'
			OR r.snapshot->>'kind' IS DISTINCT FROM 'nota'
			OR r.snapshot->>'id' IS DISTINCT FROM r.batch_key || '-' || r.ordinal::text
			OR r.snapshot->>'revision' IS DISTINCT FROM r.revision::text)
	) AND NOT EXISTS (
		SELECT 1 FROM pavarotti_code_triage t JOIN pavarotti_evidence_batches b USING (expediente, batch_key)
		WHERE t.expediente = $1 AND (t.ordinal > jsonb_array_length(b.payload)
			OR t.finding_key !~ '^[a-f0-9]{64}$'
			OR t.entry->>'revision' IS DISTINCT FROM t.revision::text)
	) AND NOT EXISTS (
		SELECT 1 FROM pavarotti_analysis_jobs j WHERE j.expediente = $1 AND (
			j.id !~ '^[a-f0-9]{32}$' OR j.fingerprint !~ '^[a-f0-9]{64}$'
			OR (j.state = 'succeeded' AND jsonb_typeof(j.result) IS DISTINCT FROM 'object'))
	) AND NOT EXISTS (
		SELECT 1 FROM pavarotti_audit_events e JOIN pavarotti_audit_heads h USING (expediente)
		WHERE e.expediente = $1 AND e.position > h.position
	)`, s.expediente).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("%w: referencias internas del expediente", ErrBackupIntegrity)
	}
	return nil
}
