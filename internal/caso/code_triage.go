package caso

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const MaxTriageReason = 2000

var ErrInvalidTriage = errors.New("la clasificación requiere un estado válido y una justificación de hasta 2000 bytes")

type FindingKey struct {
	Rule   string `json:"rule"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

type CodeDisposition struct {
	FindingKey
	Revision int    `json:"revision"`
	Status   string `json:"status"`
	Reason   string `json:"reason"`
	Time     string `json:"time"`
}

func (finding Finding) Key() FindingKey {
	return FindingKey{Rule: finding.Rule, Line: finding.Line, Column: finding.Column}
}

func (key FindingKey) hash() string {
	return Hash([]byte(fmt.Sprintf("%d:%d:%s", key.Line, key.Column, key.Rule)))
}

func (record Record) hasSignal(key FindingKey) bool {
	review := record.StaticReview()
	return review != nil && slices.ContainsFunc(review.Signals, func(f Finding) bool { return f.Key() == key })
}

func (s *Store) CodeHistory(ctx context.Context, id string, key FindingKey) ([]CodeDisposition, error) {
	record, err := s.Record(ctx, id)
	if err != nil {
		return nil, err
	}
	if !record.hasSignal(key) {
		return nil, ErrNotFound
	}
	if s.db != nil {
		batch, ordinal, _ := recordPosition(id)
		ctx, cancel := context.WithTimeout(ctx, operationTimeout)
		defer cancel()
		return readCodeTriage(ctx, s.db, `SELECT entry FROM pavarotti_code_triage
			WHERE expediente = $1 AND batch_key = $2 AND ordinal = $3 AND finding_key = $4 ORDER BY revision`,
			s.expediente, batch, ordinal, key.hash())
	}
	unlock, err := s.lockContext(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	return s.localCodeHistory(id, key)
}

func (s *Store) CodeClassifications(ctx context.Context, id string) ([]CodeDisposition, error) {
	record, err := s.Record(ctx, id)
	if err != nil {
		return nil, err
	}
	if record.StaticReview() == nil {
		return nil, ErrNotFound
	}
	if s.db != nil {
		ctx, cancel := context.WithTimeout(ctx, operationTimeout)
		defer cancel()
		batch, ordinal, _ := recordPosition(id)
		return readCodeTriage(ctx, s.db, `SELECT DISTINCT ON (finding_key) entry FROM pavarotti_code_triage
			WHERE expediente = $1 AND batch_key = $2 AND ordinal = $3 ORDER BY finding_key, revision DESC`,
			s.expediente, batch, ordinal)
	}
	unlock, err := s.lockContext(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	current := make([]CodeDisposition, 0)
	err = s.walkLocalTriage(record, func(history []CodeDisposition) error {
		current = append(current, history[len(history)-1])
		return nil
	})
	return current, err
}

func (s *Store) ClassifyCode(ctx context.Context, id string, key FindingKey, expected int, status, reason string) (CodeDisposition, error) {
	reason = strings.TrimSpace(reason)
	if expected < 0 || expected == math.MaxInt || !validCodeDisposition(status, reason) {
		return CodeDisposition{}, ErrInvalidTriage
	}
	record, err := s.Record(ctx, id)
	if err != nil {
		return CodeDisposition{}, err
	}
	if !record.hasSignal(key) {
		return CodeDisposition{}, ErrNotFound
	}
	next := CodeDisposition{FindingKey: key, Revision: expected + 1, Status: status, Reason: reason}
	if s.db != nil {
		batch, ordinal, _ := recordPosition(id)
		return s.classifyCodePostgres(ctx, batch, ordinal, next)
	}
	unlock, err := s.lockContext(ctx)
	if err != nil {
		return CodeDisposition{}, err
	}
	defer unlock()
	history, err := s.localCodeHistory(id, key)
	if err != nil {
		return CodeDisposition{}, err
	}
	if len(history) != expected {
		return CodeDisposition{}, ErrRevisionConflict
	}
	next.Time = Now()
	data, err := json.Marshal(append(history, next))
	if err != nil {
		return CodeDisposition{}, err
	}
	file := s.codeTriagePath(id, key)
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		return CodeDisposition{}, err
	}
	if err := atomicWrite(file, data); err != nil {
		return CodeDisposition{}, err
	}
	return next, nil
}

func validCodeDisposition(status, reason string) bool {
	return (status == "pendiente" || status == "confirmada" || status == "descartada") &&
		reason != "" && len(reason) <= MaxTriageReason && utf8.ValidString(reason) &&
		!strings.ContainsFunc(reason, func(char rune) bool { return unicode.IsControl(char) && char != '\n' && char != '\t' && char != '\r' })
}

func (s *Store) codeTriagePath(id string, key FindingKey) string {
	return filepath.Join(s.path, ".clasificaciones", id, key.hash()+".json")
}

func (s *Store) localCodeHistory(id string, key FindingKey) ([]CodeDisposition, error) {
	data, err := os.ReadFile(s.codeTriagePath(id, key))
	if errors.Is(err, os.ErrNotExist) {
		return []CodeDisposition{}, nil
	}
	if err != nil {
		return nil, err
	}
	var history []CodeDisposition
	if err := json.Unmarshal(data, &history); err != nil {
		return nil, err
	}
	for index, revision := range history {
		_, err := time.Parse(time.RFC3339Nano, revision.Time)
		if err != nil || revision.Revision != index+1 || revision.FindingKey != key || !validCodeDisposition(revision.Status, revision.Reason) {
			return nil, errors.New("historial de clasificación inválido")
		}
	}
	return history, nil
}

func (s *Store) walkLocalTriage(record Record, visit func([]CodeDisposition) error) error {
	if _, err := os.Stat(filepath.Join(s.path, ".clasificaciones", record.ID)); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	seen := make(map[FindingKey]bool)
	for _, finding := range record.StaticReview().Signals {
		key := finding.Key()
		if seen[key] {
			continue
		}
		seen[key] = true
		history, err := s.localCodeHistory(record.ID, key)
		if err != nil {
			return err
		}
		if len(history) != 0 {
			if err := visit(history); err != nil {
				return err
			}
		}
	}
	return nil
}
