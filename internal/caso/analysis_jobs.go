package caso

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

const (
	AnalysisMaxAttempts = 3
	AnalysisLease       = 15 * time.Second
)

var (
	ErrQueueUnavailable = errors.New("la cola de análisis requiere PostgreSQL")
	ErrJobState         = errors.New("la tarea ya terminó o el ejecutor perdió la asignación")
	ErrInvalidJob       = errors.New("tarea de análisis inválida")
)

type AnalysisJob struct {
	ID           string          `json:"id"`
	Fingerprint  string          `json:"sha256"`
	AgentVersion string          `json:"agent_version"`
	State        string          `json:"state"`
	Priority     int             `json:"priority"`
	Attempts     int             `json:"attempts"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
	Error        string          `json:"error,omitempty"`
	Result       json.RawMessage `json:"result,omitempty"`
}

type AnalysisClaim struct {
	Job      AnalysisJob
	Token    string
	Snapshot json.RawMessage
}

const jobFields = "id, fingerprint, agent_version, state, priority, attempts, created_at, updated_at, failure"

func migrateAnalysisQueue(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS pavarotti_analysis_jobs (
			expediente TEXT NOT NULL,
			id TEXT NOT NULL,
			fingerprint TEXT NOT NULL,
			agent_version TEXT NOT NULL,
			priority SMALLINT NOT NULL CHECK (priority BETWEEN 0 AND 2),
			state TEXT NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','running','succeeded','failed','canceled')),
			attempts SMALLINT NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 3),
			created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
			snapshot JSONB NOT NULL CHECK (jsonb_typeof(snapshot) = 'object'),
			result JSONB,
			failure TEXT NOT NULL DEFAULT '',
			lease_until TIMESTAMPTZ,
			lease_token TEXT,
			PRIMARY KEY (expediente, id),
			CHECK ((state = 'running') = (lease_until IS NOT NULL AND lease_token IS NOT NULL)),
			CHECK ((state = 'succeeded') = (result IS NOT NULL))
		)`)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		CREATE UNIQUE INDEX IF NOT EXISTS pavarotti_jobs_unique_input
		ON pavarotti_analysis_jobs (expediente, agent_version, fingerprint)
		WHERE state IN ('queued','running','succeeded')`)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		CREATE INDEX IF NOT EXISTS pavarotti_jobs_claim
		ON pavarotti_analysis_jobs (expediente, agent_version, priority DESC, created_at, id)
		WHERE state IN ('queued','running')`)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		CREATE INDEX IF NOT EXISTS pavarotti_jobs_recent
		ON pavarotti_analysis_jobs (expediente, created_at DESC, id DESC)`)
	return err
}

func (s *Store) HasAnalysisQueue() bool { return s.db != nil }

func (s *Store) EnqueueAnalysis(ctx context.Context, fingerprint, version string, priority int, snapshot json.RawMessage) (AnalysisJob, error) {
	if !s.HasAnalysisQueue() {
		return AnalysisJob{}, ErrQueueUnavailable
	}
	if !isBatchKey(fingerprint) || version == "" || len(version) > 32 || priority < 0 || priority > 2 ||
		len(snapshot) > 33<<20 || !jsonObject(snapshot) {
		return AnalysisJob{}, ErrInvalidJob
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	var row AnalysisJob
	scan := s.db.QueryRowContext(ctx, `
		INSERT INTO pavarotti_analysis_jobs (expediente,id,fingerprint,agent_version,priority,snapshot)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (expediente,agent_version,fingerprint) WHERE state IN ('queued','running','succeeded')
		DO UPDATE SET priority = CASE WHEN pavarotti_analysis_jobs.state = 'queued'
			THEN greatest(pavarotti_analysis_jobs.priority, excluded.priority) ELSE pavarotti_analysis_jobs.priority END
		RETURNING `+jobFields, s.expediente, randomKey(), fingerprint, version, priority, []byte(snapshot))
	err := scan.Scan(row.fields()...)
	return row, err
}

func (s *Store) ClaimAnalysis(ctx context.Context, versions ...string) (AnalysisClaim, bool, error) {
	if !s.HasAnalysisQueue() {
		return AnalysisClaim{}, false, ErrQueueUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if _, err := s.db.ExecContext(ctx, `
		UPDATE pavarotti_analysis_jobs
		SET state = 'failed', lease_until = NULL, lease_token = NULL, updated_at = clock_timestamp(),
		    failure = 'Se agotaron los intentos de recuperar el análisis'
		WHERE expediente = $1 AND agent_version = ANY($2::text[]) AND state = 'running'
		  AND lease_until <= clock_timestamp() AND attempts >= $3
	`, s.expediente, versions, AnalysisMaxAttempts); err != nil {
		return AnalysisClaim{}, false, err
	}
	claim := AnalysisClaim{Token: randomKey()}
	row := s.db.QueryRowContext(ctx, `
		WITH candidate AS (
			SELECT id AS next_id FROM pavarotti_analysis_jobs
			WHERE expediente = $1 AND agent_version = ANY($2::text[]) AND attempts < $3
			  AND (state = 'queued' OR (state = 'running' AND lease_until <= clock_timestamp()))
			ORDER BY priority DESC, created_at, id FOR UPDATE SKIP LOCKED LIMIT 1
		)
		UPDATE pavarotti_analysis_jobs
		SET state = 'running', attempts = attempts + 1, updated_at = clock_timestamp(),
		    lease_until = clock_timestamp() + $4::bigint * interval '1 millisecond', lease_token = $5
		FROM candidate WHERE expediente = $1 AND id = candidate.next_id
		RETURNING `+jobFields+`, snapshot`, s.expediente, versions, AnalysisMaxAttempts, AnalysisLease.Milliseconds(), claim.Token)
	err := row.Scan(append(claim.Job.fields(), &claim.Snapshot)...)
	if errors.Is(err, sql.ErrNoRows) {
		return AnalysisClaim{}, false, nil
	}
	return claim, err == nil, err
}

func (s *Store) RenewAnalysis(ctx context.Context, claim AnalysisClaim) error {
	return s.updateAnalysisClaim(ctx, claim, `
		UPDATE pavarotti_analysis_jobs SET lease_until = clock_timestamp() + $4::bigint * interval '1 millisecond'
		WHERE expediente = $1 AND id = $2 AND state = 'running' AND lease_token = $3 AND lease_until > clock_timestamp()
	`, AnalysisLease.Milliseconds())
}

func (s *Store) FinishAnalysis(ctx context.Context, claim AnalysisClaim, payload json.RawMessage, failure string) error {
	state := "succeeded"
	var result any = []byte(payload)
	if failure != "" {
		state, result = "failed", nil
	} else if !jsonObject(payload) {
		return ErrInvalidJob
	}
	return s.updateAnalysisClaim(ctx, claim, `
		UPDATE pavarotti_analysis_jobs SET state = $4, result = $5, failure = $6, updated_at = clock_timestamp(),
		    lease_until = NULL, lease_token = NULL
		WHERE expediente = $1 AND id = $2 AND state = 'running' AND lease_token = $3 AND lease_until > clock_timestamp()
	`, state, result, failure)
}

func (s *Store) updateAnalysisClaim(ctx context.Context, claim AnalysisClaim, query string, extra ...any) error {
	if !s.HasAnalysisQueue() {
		return ErrQueueUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	result, err := s.db.ExecContext(ctx, query, append([]any{s.expediente, claim.Job.ID, claim.Token}, extra...)...)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err == nil && count == 0 {
		return ErrJobState
	}
	return err
}

func (s *Store) AnalysisJobs(ctx context.Context) ([]AnalysisJob, error) {
	if !s.HasAnalysisQueue() {
		return nil, ErrQueueUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+jobFields+` FROM pavarotti_analysis_jobs
		WHERE expediente = $1 ORDER BY (state IN ('queued','running')) DESC, created_at DESC, id DESC LIMIT 50
	`, s.expediente)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	jobs := make([]AnalysisJob, 0)
	for rows.Next() {
		var job AnalysisJob
		if err := rows.Scan(job.fields()...); err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}

func (s *Store) AnalysisJob(ctx context.Context, id string) (AnalysisJob, error) {
	if !s.HasAnalysisQueue() {
		return AnalysisJob{}, ErrQueueUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	var job AnalysisJob
	if !validJobID(id) {
		return job, ErrNotFound
	}
	row := s.db.QueryRowContext(ctx, `SELECT `+jobFields+`, result FROM pavarotti_analysis_jobs WHERE expediente = $1 AND id = $2`, s.expediente, id)
	var result []byte
	err := row.Scan(append(job.fields(), &result)...)
	if errors.Is(err, sql.ErrNoRows) {
		return job, ErrNotFound
	}
	job.Result = result
	return job, err
}

func (s *Store) CancelAnalysis(ctx context.Context, id string) (AnalysisJob, error) {
	if !s.HasAnalysisQueue() {
		return AnalysisJob{}, ErrQueueUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	var job AnalysisJob
	if !validJobID(id) {
		return job, ErrNotFound
	}
	row := s.db.QueryRowContext(ctx, `
		UPDATE pavarotti_analysis_jobs SET state = 'canceled', lease_until = NULL,
		    lease_token = NULL, updated_at = clock_timestamp()
		WHERE expediente = $1 AND id = $2 AND state IN ('queued','running')
		RETURNING `+jobFields, s.expediente, id)
	if err := row.Scan(job.fields()...); !errors.Is(err, sql.ErrNoRows) {
		return job, err
	}
	job, err := s.AnalysisJob(ctx, id)
	if err == nil && job.State != "canceled" {
		err = ErrJobState
	}
	return job, err
}

func (job *AnalysisJob) fields() []any {
	return []any{&job.ID, &job.Fingerprint, &job.AgentVersion, &job.State, &job.Priority, &job.Attempts,
		&job.CreatedAt, &job.UpdatedAt, &job.Error}
}

func randomKey() string {
	var buf [16]byte
	rand.Read(buf[:])
	return hex.EncodeToString(buf[:])
}

func validJobID(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func jsonObject(data []byte) bool {
	data = bytes.TrimSpace(data)
	return len(data) > 0 && data[0] == '{' && json.Valid(data)
}
