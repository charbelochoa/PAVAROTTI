package caso

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/flock"
)

type Record struct {
	ID        string   `json:"id,omitempty"`
	Revision  int      `json:"revision,omitempty"`
	UpdatedAt string   `json:"updated_at,omitempty"`
	Kind      string   `json:"kind"`
	Time      string   `json:"time"`
	Title     string   `json:"title"`
	Source    string   `json:"source,omitempty"`
	SourceID  string   `json:"source_id,omitempty"`
	SHA256    string   `json:"sha256,omitempty"`
	Details   string   `json:"details,omitempty"`
	Signals   []string `json:"signals,omitempty"`
	Traffic   *Traffic `json:"traffic,omitempty"`
}

type Traffic struct {
	Method string `json:"method"`
	Status int    `json:"status"`
	Type   string `json:"type"`
	Millis int64  `json:"millis"`
	Bucket int64  `json:"bucket"`
}

type Store struct {
	path       string
	db         *sql.DB
	expediente string
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
		return s.db.Close()
	}
	return nil
}

func (s *Store) Save(records []Record) error {
	if len(records) == 0 {
		return nil
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
		return err
	}
	hash := Hash(data)
	if records[0].SHA256 != "" {
		hash = Hash([]byte(records[0].Kind + ":" + records[0].SHA256))
	}
	if s.db != nil {
		ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
		defer cancel()
		_, err = s.db.ExecContext(ctx, `
			INSERT INTO pavarotti_evidence_batches (expediente, batch_key, payload)
			VALUES ($1, $2, $3) ON CONFLICT (expediente, batch_key) DO NOTHING`,
			s.expediente, hash, data)
		return err
	}
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	name := filepath.Join(s.path, hash+".json")
	if _, err := os.Stat(name); !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return atomicWrite(name, data)
}

func (s *Store) Records() ([]Record, error) {
	if s.db != nil {
		return s.postgresRecords()
	}
	unlock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	entries, err := os.ReadDir(s.path)
	if err != nil {
		return nil, err
	}
	records := make([]Record, 0)
	for _, entry := range entries {
		key, isJSON := strings.CutSuffix(entry.Name(), ".json")
		if !entry.Type().IsRegular() || !isJSON || !isBatchKey(key) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.path, entry.Name()))
		if err != nil {
			return nil, err
		}
		batch, err := decodeBatch(key, data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", entry.Name(), err)
		}
		for i, record := range batch {
			if record.Kind != "nota" {
				continue
			}
			edits, err := s.localEdits(record.ID)
			if err != nil {
				return nil, err
			}
			if len(edits) > 0 {
				batch[i] = edits[len(edits)-1]
			}
		}
		records = append(records, batch...)
	}
	return records, nil
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
	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
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
