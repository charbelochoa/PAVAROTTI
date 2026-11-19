package caso

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"maps"
	"time"
)

const (
	caseBackupFormat  = "pavarotti.case-backup"
	caseBackupVersion = 1
	maxBackupLine     = 256 << 20
)

var (
	ErrBackupUnavailable = errors.New("el respaldo integral requiere PostgreSQL")
	ErrBackupVersion     = errors.New("formato o versión de respaldo incompatible")
	ErrBackupIntegrity   = errors.New("el respaldo está incompleto o su contenido es inválido")
	ErrBackupRowSize     = errors.New("una fila del respaldo supera el límite de 256 MiB")
	ErrBackupDestination = errors.New("restaura en un expediente PostgreSQL vacío")
)

type BackupManifest struct {
	Format     string    `json:"format"`
	Version    int       `json:"version"`
	SourceCase string    `json:"source_case"`
	CreatedAt  time.Time `json:"created_at"`
}

type BackupSummary struct {
	BackupManifest
	SHA256 string         `json:"sha256"`
	Rows   map[string]int `json:"rows"`
}

type backupFrame struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

type backupFooter struct {
	SHA256 string         `json:"sha256"`
	Rows   map[string]int `json:"rows"`
}

func (s *Store) BackupCase(ctx context.Context, destination io.Writer) (BackupSummary, error) {
	if s.db == nil {
		return BackupSummary{}, ErrBackupUnavailable
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return BackupSummary{}, err
	}
	defer tx.Rollback()
	manifest := BackupManifest{Format: caseBackupFormat, Version: caseBackupVersion, SourceCase: s.expediente}
	if err := tx.QueryRowContext(ctx, `SELECT transaction_timestamp()`).Scan(&manifest.CreatedAt); err != nil {
		return BackupSummary{}, err
	}
	manifest.CreatedAt = manifest.CreatedAt.UTC()
	digest := sha256.New()
	buffer := bufio.NewWriterSize(destination, 64<<10)
	writer := io.MultiWriter(buffer, digest)
	if err := encodeBackupFrame(writer, "header", manifest); err != nil {
		return BackupSummary{}, err
	}
	counts := newBackupCounts()
	for _, table := range caseBackupTables {
		count, err := table.export(ctx, tx, s.expediente, writer)
		if err != nil {
			return BackupSummary{}, fmt.Errorf("respaldar %s: %w", table.kind, err)
		}
		counts[table.kind] = count
	}
	if err := tx.Commit(); err != nil {
		return BackupSummary{}, err
	}
	sum := hex.EncodeToString(digest.Sum(nil))
	if err := encodeBackupFrame(buffer, "end", backupFooter{SHA256: sum, Rows: counts}); err != nil {
		return BackupSummary{}, err
	}
	if err := buffer.Flush(); err != nil {
		return BackupSummary{}, err
	}
	return BackupSummary{BackupManifest: manifest, SHA256: sum, Rows: counts}, nil
}

func newBackupCounts() map[string]int {
	counts := make(map[string]int, len(caseBackupTables))
	for _, table := range caseBackupTables {
		counts[table.kind] = 0
	}
	return counts
}

func encodeBackupFrame(writer io.Writer, kind string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	return writeBackupFrame(writer, kind, data)
}

func writeBackupFrame(writer io.Writer, kind string, body []byte) error {
	prefix := `{"type":"` + kind + `","data":`
	if len(prefix)+len(body)+2 >= maxBackupLine {
		return ErrBackupRowSize
	}
	if _, err := io.WriteString(writer, prefix); err != nil {
		return err
	}
	if _, err := writer.Write(body); err != nil {
		return err
	}
	_, err := io.WriteString(writer, "}\n")
	return err
}

type backupReader struct {
	scanner  *bufio.Scanner
	digest   hash.Hash
	manifest BackupManifest
}

func openBackup(ctx context.Context, source io.Reader) (*backupReader, error) {
	reader := &backupReader{scanner: bufio.NewScanner(source), digest: sha256.New()}
	reader.scanner.Buffer(make([]byte, 64<<10), maxBackupLine)
	reader.scanner.Split(splitBackupLine)
	frame, err := reader.next(ctx)
	if err != nil {
		return nil, err
	}
	if frame.Type != "header" || json.Unmarshal(frame.Data, &reader.manifest) != nil ||
		reader.manifest.SourceCase == "" || len(reader.manifest.SourceCase) > 120 || reader.manifest.CreatedAt.IsZero() {
		return nil, ErrBackupIntegrity
	}
	if reader.manifest.Format != caseBackupFormat || reader.manifest.Version != caseBackupVersion {
		return nil, ErrBackupVersion
	}
	return reader, nil
}

func splitBackupLine(data []byte, eof bool) (int, []byte, error) {
	if index := bytes.IndexByte(data, '\n'); index >= 0 {
		return index + 1, data[:index+1], nil
	}
	if eof && len(data) != 0 {
		return 0, nil, ErrBackupIntegrity
	}
	return 0, nil, nil
}

func (reader *backupReader) next(ctx context.Context) (backupFrame, error) {
	var frame backupFrame
	if err := ctx.Err(); err != nil {
		return frame, err
	}
	if !reader.scanner.Scan() {
		return frame, errors.Join(ErrBackupIntegrity, reader.scanner.Err())
	}
	line := reader.scanner.Bytes()
	if json.Unmarshal(line, &frame) != nil {
		return frame, ErrBackupIntegrity
	}
	if data := bytes.TrimSpace(frame.Data); len(data) == 0 || data[0] != '{' {
		return frame, ErrBackupIntegrity
	}
	if frame.Type != "end" {
		_, _ = reader.digest.Write(line)
	}
	return frame, nil
}

func (reader *backupReader) readRows(ctx context.Context, apply func(caseBackupTable, json.RawMessage) error) (BackupSummary, error) {
	counts := newBackupCounts()
	lastTable := 0
	for {
		frame, err := reader.next(ctx)
		if err != nil {
			return BackupSummary{}, err
		}
		if frame.Type == "end" {
			return reader.finish(frame.Data, counts)
		}
		for lastTable < len(caseBackupTables) && caseBackupTables[lastTable].kind != frame.Type {
			lastTable++
		}
		if lastTable == len(caseBackupTables) {
			return BackupSummary{}, ErrBackupIntegrity
		}
		if err := apply(caseBackupTables[lastTable], frame.Data); err != nil {
			return BackupSummary{}, err
		}
		counts[frame.Type]++
	}
}

func (reader *backupReader) finish(data []byte, counts map[string]int) (BackupSummary, error) {
	var sealed backupFooter
	sum := hex.EncodeToString(reader.digest.Sum(nil))
	if json.Unmarshal(data, &sealed) != nil || sealed.SHA256 != sum || !maps.Equal(sealed.Rows, counts) || reader.scanner.Scan() || reader.scanner.Err() != nil {
		return BackupSummary{}, ErrBackupIntegrity
	}
	return BackupSummary{BackupManifest: reader.manifest, SHA256: sum, Rows: counts}, nil
}

func InspectCaseBackup(ctx context.Context, source io.Reader) (BackupSummary, error) {
	reader, err := openBackup(ctx, source)
	if err != nil {
		return BackupSummary{}, err
	}
	return reader.readRows(ctx, func(caseBackupTable, json.RawMessage) error { return nil })
}
