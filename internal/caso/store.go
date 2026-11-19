package caso

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Record struct {
	Kind     string   `json:"kind"`
	Time     string   `json:"time"`
	Title    string   `json:"title"`
	Source   string   `json:"source,omitempty"`
	SourceID string   `json:"source_id,omitempty"`
	SHA256   string   `json:"sha256,omitempty"`
	Details  string   `json:"details,omitempty"`
	Signals  []string `json:"signals,omitempty"`
}

type Store struct {
	path string
	mu   sync.Mutex
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(path, 0700); err != nil {
		return nil, err
	}
	return &Store{path: path}, nil
}

func Now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func Hash(input []byte) string { return fmt.Sprintf("%x", sha256.Sum256(input)) }

func (s *Store) Save(records []Record) error {
	if len(records) == 0 {
		return nil
	}
	data, err := json.Marshal(records)
	if err != nil {
		return err
	}
	hash := Hash(data)
	if records[0].SHA256 != "" {
		hash = Hash([]byte(records[0].Kind + ":" + records[0].SHA256))
	}
	name := filepath.Join(s.path, hash+".json")
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := os.Stat(name); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.CreateTemp(s.path, ".registro-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(data)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), name); err != nil {
		if _, check := os.Stat(name); check == nil {
			return nil
		}
		return err
	}
	return nil
}

func (s *Store) Records() ([]Record, error) {
	entries, err := os.ReadDir(s.path)
	if err != nil {
		return nil, err
	}
	records := make([]Record, 0)
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.path, entry.Name()))
		if err != nil {
			return nil, err
		}
		var batch []Record
		if err := json.Unmarshal(data, &batch); err != nil {
			return nil, fmt.Errorf("%s: %w", entry.Name(), err)
		}
		records = append(records, batch...)
	}
	return records, nil
}
