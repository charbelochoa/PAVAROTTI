package ingesta

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
	"unicode"

	"pavarotti/internal/caso"
	"pavarotti/internal/revision"
)

const (
	MaxDirectoryFiles   = 200
	MaxDirectoryBytes   = 32 << 20
	maxDirectoryEntries = 30000
)

var (
	ErrDirectoryLimit = errors.New("la revisión admite hasta 200 archivos compatibles, 30000 entradas recorridas y 32 MiB de entrada")
	ErrDirectoryPath  = errors.New("ruta relativa inválida o duplicada en la selección")
	ErrDirectoryEmpty = errors.New("la selección requiere archivos Go, go.mod o package-lock.json")
)

type DirectoryResult struct {
	caso.SaveResult
	Rejected int             `json:"rejected"`
	Files    []DirectoryFile `json:"files"`
}

func (result DirectoryResult) Message() string {
	return fmt.Sprintf("%s · rechazados %d", result.SaveResult.Message(), result.Rejected)
}

type DirectoryFile struct {
	Path   string `json:"path"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

type directoryItem struct {
	file   DirectoryFile
	record *caso.Record
}

type DirectoryReview struct {
	items map[string]directoryItem
	bytes int
}

func (review *DirectoryReview) Add(name string, source io.Reader) error {
	if !validDirectoryPath(name) || directoryKind(name) == "" || slices.ContainsFunc(strings.Split(name, "/"), excludedDirectory) {
		return ErrDirectoryPath
	}
	if _, exists := review.items[name]; exists {
		return ErrDirectoryPath
	}
	if len(review.items) >= MaxDirectoryFiles || review.bytes >= MaxDirectoryBytes {
		return ErrDirectoryLimit
	}
	if review.items == nil {
		review.items = make(map[string]directoryItem)
	}
	kind := directoryKind(name)
	limit := revision.MaxManifest
	if kind == "codigo" {
		limit = revision.MaxSource
	}
	data, err := io.ReadAll(io.LimitReader(source, int64(min(limit, MaxDirectoryBytes-review.bytes))+1))
	if err != nil {
		return err
	}
	review.bytes += len(data)
	if review.bytes > MaxDirectoryBytes {
		return ErrDirectoryLimit
	}
	item := directoryItem{file: DirectoryFile{Path: name, Status: "pendiente"}}
	records, err := Parse(kind, bytes.NewReader(data))
	if err != nil {
		item.file.Status, item.file.Reason = "rechazado", err.Error()
	} else {
		records[0].SourceID, records[0].Directory = name, true
		item.record = &records[0]
	}
	review.items[name] = item
	return nil
}

func (review *DirectoryReview) Save(ctx context.Context, store *caso.Store) (DirectoryResult, error) {
	if len(review.items) == 0 {
		return DirectoryResult{}, ErrDirectoryEmpty
	}
	paths := make([]string, 0, len(review.items))
	for name := range review.items {
		paths = append(paths, name)
	}
	slices.Sort(paths)
	result := DirectoryResult{Files: make([]DirectoryFile, 0, len(paths))}
	var failure error
	for _, name := range paths {
		item := review.items[name]
		file := item.file
		if item.record == nil {
			result.Rejected++
		} else if failure == nil {
			outcome, err := store.SaveEvidence(ctx, []caso.Record{*item.record})
			if err != nil {
				failure = err
			} else if outcome.Imported > 0 {
				file.Status = "importado"
				result.Imported++
			} else {
				file.Status = "duplicado"
				result.Duplicates++
			}
		}
		result.Files = append(result.Files, file)
	}
	return result, failure
}

func LoadDirectory(ctx context.Context, directory string) (*DirectoryReview, error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	review := &DirectoryReview{}
	entries := 0
	err = fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		entries++
		if entries > maxDirectoryEntries {
			return ErrDirectoryLimit
		}
		if entry.IsDir() && excludedDirectory(entry.Name()) {
			return fs.SkipDir
		}
		if entry.IsDir() || !entry.Type().IsRegular() || directoryKind(name) == "" {
			return nil
		}
		file, err := root.Open(name)
		if err != nil {
			return err
		}
		defer file.Close()
		return review.Add(name, file)
	})
	return review, err
}

func directoryKind(name string) string {
	base := strings.ToLower(path.Base(name))
	switch base {
	case "go.mod":
		return "gomod"
	case "package-lock.json":
		return "npmlock"
	}
	if path.Ext(base) == ".go" {
		return "codigo"
	}
	return ""
}

func validDirectoryPath(name string) bool {
	return name != "." && len(name) <= 512 && fs.ValidPath(name) && !strings.ContainsAny(name, `\:`) &&
		!strings.ContainsFunc(name, func(char rune) bool { return unicode.IsControl(char) || unicode.In(char, unicode.Cf) })
}

func excludedDirectory(name string) bool {
	switch strings.ToLower(name) {
	case ".git", "node_modules", "vendor":
		return true
	}
	return false
}
