package caso

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

var (
	ErrAuditUnavailable = errors.New("la actividad del expediente requiere PostgreSQL")
	ErrAuditPage        = errors.New("la página de actividad requiere un límite entre 1 y 100 y un cursor válido")
)

const (
	AuditEvidence = "evidencia.incorporada"
	AuditNote     = "nota.creada"
	AuditEdit     = "nota.editada"
	AuditTriage   = "senal.clasificada"
	AuditImport   = "expediente.migrado"
	AuditQueue    = "tarea.encolada"
	AuditPriority = "tarea.priorizada"
	AuditStart    = "tarea.iniciada"
	AuditFinish   = "tarea.finalizada"
	AuditCancel   = "tarea.cancelada"
)

type AuditDetails struct {
	Count           int         `json:"count,omitempty"`
	Revision        int         `json:"revision,omitempty"`
	Finding         *FindingKey `json:"finding,omitempty"`
	Status          string      `json:"status,omitempty"`
	Priority        *int        `json:"priority,omitempty"`
	Attempt         int         `json:"attempt,omitempty"`
	NoteRevisions   int         `json:"note_revisions,omitempty"`
	TriageRevisions int         `json:"triage_revisions,omitempty"`
}

type AuditEvent struct {
	Position int64        `json:"position"`
	Time     time.Time    `json:"time"`
	Actor    string       `json:"actor"`
	Source   string       `json:"source"`
	Action   string       `json:"action"`
	Target   string       `json:"target,omitempty"`
	Details  AuditDetails `json:"details"`
}

type AuditPage struct {
	Events []AuditEvent `json:"events"`
	Next   int64        `json:"next,omitempty"`
}

type auditAccount struct {
	caseName string
	name     string
}

type auditAccountKey struct{}

func (s *Store) HasAuditLog() bool { return s.db != nil }

func (s *Store) AuditContext(ctx context.Context, account SharedAccount) context.Context {
	return context.WithValue(ctx, auditAccountKey{}, auditAccount{caseName: s.expediente, name: account.Name})
}

func migrateAudit(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS pavarotti_audit_heads (
		expediente TEXT PRIMARY KEY,
		position BIGINT NOT NULL CHECK (position > 0)
	)`); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS pavarotti_audit_events (
		expediente TEXT NOT NULL REFERENCES pavarotti_audit_heads (expediente),
		position BIGINT NOT NULL CHECK (position > 0),
		occurred_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
		actor TEXT NOT NULL,
		source TEXT NOT NULL CHECK (source IN ('sesion', 'postgres')),
		action TEXT NOT NULL,
		target TEXT NOT NULL,
		details JSONB NOT NULL CHECK (jsonb_typeof(details) = 'object'),
		PRIMARY KEY (expediente, position)
	)`)
	return err
}

func (s *Store) appendAudit(ctx context.Context, tx *sql.Tx, action, target string, details AuditDetails) error {
	actor := ""
	if identity, ok := ctx.Value(auditAccountKey{}).(auditAccount); ok && identity.caseName == s.expediente {
		actor = identity.name
	}
	payload, err := json.Marshal(details)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `WITH sequence AS (
		INSERT INTO pavarotti_audit_heads (expediente, position) VALUES ($1, 1)
		ON CONFLICT (expediente) DO UPDATE SET position = pavarotti_audit_heads.position + 1
		RETURNING position
	)
	INSERT INTO pavarotti_audit_events (expediente, position, actor, source, action, target, details)
	SELECT $1, position, COALESCE(NULLIF($2, ''), CURRENT_USER::text),
	       CASE WHEN $2 = '' THEN 'postgres' ELSE 'sesion' END, $3, $4, $5::jsonb FROM sequence`,
		s.expediente, actor, action, target, payload)
	return err
}

func (s *Store) AuditPage(ctx context.Context, before int64, limit int) (AuditPage, error) {
	if !s.HasAuditLog() {
		return AuditPage{}, ErrAuditUnavailable
	}
	if before < 0 || limit < 1 || limit > 100 {
		return AuditPage{}, ErrAuditPage
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `SELECT position, occurred_at, actor, source, action, target, details
		FROM pavarotti_audit_events WHERE expediente = $1 AND ($2::bigint = 0 OR position < $2)
		ORDER BY position DESC LIMIT $3`, s.expediente, before, limit+1)
	if err != nil {
		return AuditPage{}, err
	}
	defer rows.Close()
	page := AuditPage{Events: make([]AuditEvent, 0, limit)}
	for rows.Next() {
		var event AuditEvent
		var details []byte
		if err := rows.Scan(&event.Position, &event.Time, &event.Actor, &event.Source, &event.Action, &event.Target, &details); err != nil {
			return AuditPage{}, err
		}
		if err := json.Unmarshal(details, &event.Details); err != nil {
			return AuditPage{}, err
		}
		if len(page.Events) == limit {
			page.Next = page.Events[limit-1].Position
			break
		}
		page.Events = append(page.Events, event)
	}
	return page, rows.Err()
}
