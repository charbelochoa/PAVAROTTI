package caso

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/flock"
)

type Record struct {
	ID           string               `json:"id,omitempty"`
	Revision     int                  `json:"revision,omitempty"`
	UpdatedAt    string               `json:"updated_at,omitempty"`
	Kind         string               `json:"kind"`
	Time         string               `json:"time"`
	Title        string               `json:"title"`
	Source       string               `json:"source,omitempty"`
	SourceID     string               `json:"source_id,omitempty"`
	Directory    bool                 `json:"directory,omitempty"`
	SHA256       string               `json:"sha256,omitempty"`
	Details      string               `json:"details,omitempty"`
	Network      string               `json:"network,omitempty"`
	Signals      []string             `json:"signals,omitempty"`
	HTTPFindings []HTTPFinding        `json:"http_findings,omitempty"`
	HTTPRuleSet  int                  `json:"http_rule_set,omitempty"`
	Traffic      *Traffic             `json:"traffic,omitempty"`
	Indicator    *Indicator           `json:"indicator,omitempty"`
	FileHashes   []Indicator          `json:"file_hashes,omitempty"`
	STIX         *STIXObject          `json:"stix,omitempty"`
	Review       *CodeReview          `json:"code_review,omitempty"`
	Dependencies *DependencyInventory `json:"dependencies,omitempty"`

	BinaryListing int `json:"binary_listing,omitempty"`
}

type Indicator struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Traffic struct {
	Method string `json:"method"`
	Status int    `json:"status"`
	Type   string `json:"type"`
	Millis int64  `json:"millis"`
	Bucket int64  `json:"bucket"`
}

type HTTPFinding struct {
	Rule        string `json:"rule"`
	Label       string `json:"label"`
	Header      string `json:"header,omitempty"`
	Observation string `json:"observation,omitempty"`
}

const ProxyNoResponseSignal = "El proxy no recibió respuesta del destino"

type Store struct {
	path       string
	db         *sql.DB
	expediente string
	batchDates localBatchDates
	pageCache  localPageCache
	searchWork postgresPageWorker
	httpWork   postgresPageWorker
}

const operationTimeout = 15 * time.Second

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(path, 0700); err != nil {
		return nil, err
	}
	return &Store{path: path}, nil
}

func Now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func Hash(input []byte) string { return fmt.Sprintf("%x", sha256.Sum256(input)) }

func (s *Store) Close() error {
	if s.db != nil {
		s.searchWork.stop()
		s.httpWork.stop()
		return s.db.Close()
	}
	return nil
}

func (s *Store) Save(records []Record) error {
	_, err := s.SaveEvidence(context.Background(), records)
	return err
}

type SaveResult struct {
	Imported   int `json:"imported"`
	Duplicates int `json:"duplicates"`
}

func (result SaveResult) Message() string {
	return fmt.Sprintf("Importados %d · duplicados %d", result.Imported, result.Duplicates)
}

func (s *Store) SaveEvidence(ctx context.Context, records []Record) (SaveResult, error) {
	if err := ctx.Err(); err != nil {
		return SaveResult{}, err
	}
	if len(records) == 0 {
		return SaveResult{}, nil
	}
	initial := make([]Record, len(records))
	copy(initial, records)
	for i := range initial {
		initial[i].ID = ""
		initial[i].Revision = 0
		initial[i].UpdatedAt = ""
	}
	data, err := json.Marshal(initial)
	if err != nil {
		return SaveResult{}, err
	}
	hash := Hash(data)
	if records[0].SHA256 != "" {
		identity := records[0].Kind + ":" + records[0].SHA256
		if records[0].Directory {
			identity += ":" + records[0].SourceID
		}
		if records[0].Kind == "binario" && records[0].BinaryListing > 0 {
			identity += ":listado:" + strconv.Itoa(records[0].BinaryListing)
		}
		hash = Hash([]byte(identity))
	}
	if s.db != nil {
		ctx, cancel := context.WithTimeout(ctx, operationTimeout)
		defer cancel()
		tx, err := s.beginCaseWrite(ctx, false)
		if err != nil {
			return SaveResult{}, err
		}
		defer tx.Rollback()
		result, err := tx.ExecContext(ctx, `
			INSERT INTO pavarotti_evidence_batches (expediente, batch_key, payload)
			VALUES ($1, $2, $3) ON CONFLICT (expediente, batch_key) DO NOTHING`,
			s.expediente, hash, data)
		if err != nil {
			return SaveResult{}, err
		}
		inserted, err := result.RowsAffected()
		if err != nil {
			return SaveResult{}, err
		}
		if inserted == 0 {
			return SaveResult{Duplicates: len(records)}, nil
		}
		action := AuditEvidence
		if len(records) == 1 && records[0].Kind == "nota" {
			action = AuditNote
		}
		if err := s.appendAudit(ctx, tx, action, hash+"-1", AuditDetails{Count: len(records), Revision: 1}); err != nil {
			return SaveResult{}, err
		}
		if err := tx.Commit(); err != nil {
			return SaveResult{}, err
		}
		return SaveResult{Imported: len(records)}, nil
	}
	unlock, err := s.lockContext(ctx)
	if err != nil {
		return SaveResult{}, err
	}
	defer unlock()
	name := filepath.Join(s.path, hash+".json")
	if info, err := os.Stat(name); err == nil {
		if !info.Mode().IsRegular() {
			return SaveResult{}, errors.New("el destino de la evidencia no es un archivo")
		}
		return SaveResult{Duplicates: len(records)}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return SaveResult{}, err
	}
	if err := atomicWrite(name, data); err != nil {
		return SaveResult{}, err
	}
	return SaveResult{Imported: len(records)}, nil
}

func (s *Store) Records() ([]Record, error) {
	records := make([]Record, 0)
	err := s.Walk(context.Background(), func(record Record) error {
		records = append(records, record)
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(records, func(a, b Record) int {
		keyA, ordinalA, _ := recordPosition(a.ID)
		keyB, ordinalB, _ := recordPosition(b.ID)
		if keyA != keyB {
			return strings.Compare(keyA, keyB)
		}
		return ordinalA - ordinalB
	})
	return records, nil
}

func (s *Store) Walk(ctx context.Context, visit func(Record) error) error {
	if s.db != nil {
		return s.postgresWalk(ctx, visit)
	}
	return s.walkLocal(ctx, true, visit)
}

func (s *Store) walkLocal(ctx context.Context, withEdits bool, visit func(Record) error) error {
	return s.walkLocalFiltered(ctx, withEdits, EvidenceFilter{}, visit)
}

func (s *Store) walkLocalFiltered(ctx context.Context, withEdits bool, filter EvidenceFilter, visit func(Record) error) error {
	unlock, err := s.lockContext(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	return s.walkLocalBatches(ctx, func(key string, entry os.DirEntry) error {
		var info os.FileInfo
		var dates batchDates
		var knownDates bool
		if len(filter.Periods) > 0 {
			info, err = entry.Info()
			if err != nil {
				return err
			}
			dates, knownDates = s.batchDates.lookup(key, info)
			if knownDates && !dates.matches(filter) {
				return nil
			}
		}
		data, err := os.ReadFile(filepath.Join(s.path, entry.Name()))
		if err != nil {
			return err
		}
		batch, err := decodeBatch(key, data)
		if err != nil {
			return fmt.Errorf("%s: %w", entry.Name(), err)
		}
		if info != nil && !knownDates {
			s.batchDates.remember(key, info, batch)
		}
		for _, record := range batch {
			if err := ctx.Err(); err != nil {
				return err
			}
			if !filter.matches(record) {
				continue
			}
			if withEdits {
				record, err = s.latestLocal(record)
				if err != nil {
					return err
				}
			}
			if err := visit(record); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) walkLocalBatches(ctx context.Context, visit func(string, os.DirEntry) error) error {
	folder, err := os.Open(s.path)
	if err != nil {
		return err
	}
	defer folder.Close()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries, err := folder.ReadDir(128)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		for _, entry := range entries {
			key, isJSON := strings.CutSuffix(entry.Name(), ".json")
			if !entry.Type().IsRegular() || !isJSON || !isBatchKey(key) {
				continue
			}
			if err := visit(key, entry); err != nil {
				return err
			}
		}
	}
}

func (s *Store) latestLocal(record Record) (Record, error) {
	if record.Kind != "nota" {
		return record, nil
	}
	edits, err := s.localEdits(record.ID)
	if err != nil {
		return Record{}, err
	}
	if len(edits) > 0 {
		return edits[len(edits)-1], nil
	}
	return record, nil
}

func decodeBatch(key string, data []byte) ([]Record, error) {
	var batch []Record
	if err := json.Unmarshal(data, &batch); err != nil {
		return nil, err
	}
	for i := range batch {
		batch[i].ID = key + "-" + strconv.Itoa(i+1)
		batch[i].Revision = 1
	}
	return batch, nil
}

func isBatchKey(key string) bool {
	return len(key) == sha256.Size*2 &&
		strings.IndexFunc(key, func(c rune) bool { return !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') }) == -1
}

func (s *Store) lock() (func(), error) {
	return s.lockContext(context.Background())
}

func (s *Store) lockContext(ctx context.Context) (func(), error) {
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	lock := flock.New(filepath.Join(s.path, ".pavarotti.lock"))
	acquired, err := lock.TryLockContext(ctx, 25*time.Millisecond)
	if err != nil {
		return nil, err
	}
	if !acquired {
		return nil, errors.New("el expediente está ocupado")
	}
	return func() { _ = lock.Unlock() }, nil
}

func atomicWrite(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".registro-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(data)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
