package caso

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxLocalPageCacheBytes = 32 << 20

type localPageCache struct {
	mu      sync.Mutex
	batches map[string]localPageBatch
	weight  int
}

type localPageBatch struct {
	updated time.Time
	size    int64
	weight  int
	rows    []localPageEntry
}

type localPageEntry struct {
	RecordRow
	rules []string
}

func (cache *localPageCache) lookup(key string, info os.FileInfo) ([]localPageEntry, bool) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	entry, ok := cache.batches[key]
	return entry.rows, ok && entry.size == info.Size() && entry.updated.Equal(info.ModTime())
}

func (cache *localPageCache) remember(key string, info os.FileInfo, rows []localPageEntry, weight int) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if old, present := cache.batches[key]; present {
		cache.weight -= old.weight
		delete(cache.batches, key)
	}
	if weight > maxLocalPageCacheBytes-cache.weight {
		return
	}
	if cache.batches == nil {
		cache.batches = make(map[string]localPageBatch)
	}
	cache.batches[key] = localPageBatch{updated: info.ModTime(), size: info.Size(), weight: weight, rows: rows}
	cache.weight += weight
}

func (s *Store) localPageBatch(key string, file os.DirEntry) ([]localPageEntry, error) {
	info, err := file.Info()
	if err != nil {
		return nil, err
	}
	if rows, ok := s.pageCache.lookup(key, info); ok {
		return rows, nil
	}
	data, err := os.ReadFile(filepath.Join(s.path, file.Name()))
	if err != nil {
		return nil, err
	}
	var batch []struct {
		RecordRow
		Signals []string `json:"signals"`
		Rules   []struct {
			Rule string `json:"rule"`
		} `json:"http_findings"`
	}
	if err := json.Unmarshal(data, &batch); err != nil {
		return nil, fmt.Errorf("%s: %w", file.Name(), err)
	}
	rows := make([]localPageEntry, len(batch))
	weight := 256
	for index, item := range batch {
		row := item.RecordRow
		row.ID = key + "-" + strconv.Itoa(index+1)
		row.Title = strings.Clone(clipRow(row.Title, 240))
		row.Source = strings.Clone(clipRow(row.Source, 360))
		row.SourceID = ""
		if row.Kind == "binario" {
			row.SourceID = strings.Clone(clipRow(item.SourceID, 160))
		}
		row.SignalCount = len(item.Signals)
		entry := localPageEntry{RecordRow: row, rules: make([]string, 0, len(item.Rules))}
		weight += 160 + len(row.ID) + len(row.Kind) + len(row.Time) + len(row.Title) + len(row.Source) + len(row.SourceID)
		if row.Traffic != nil {
			weight += 64 + len(row.Traffic.Method) + len(row.Traffic.Type)
			for _, finding := range item.Rules {
				entry.rules = append(entry.rules, finding.Rule)
				weight += 16 + len(finding.Rule)
			}
		} else {
			entry.rules = nil
		}
		rows[index] = entry
	}
	slices.SortFunc(rows, func(a, b localPageEntry) int {
		return compareCursor(rowCursor(b.RecordRow), rowCursor(a.RecordRow))
	})
	s.pageCache.remember(key, info, rows, weight)
	return rows, nil
}

func (s *Store) indexedLocalPage(ctx context.Context, request PageRequest, after pageCursor, limit int) ([]RecordRow, error) {
	unlock, err := s.lockContext(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	rows := make(rowHeap, 0, limit)
	err = s.walkLocalBatches(ctx, func(key string, entry os.DirEntry) error {
		batch, err := s.localPageBatch(key, entry)
		if err != nil {
			return err
		}
		first := 0
		if after.ID != "" {
			first = sort.Search(len(batch), func(index int) bool {
				return compareCursor(rowCursor(batch[index].RecordRow), after) < 0
			})
		}
		for _, item := range batch[first:] {
			if err := ctx.Err(); err != nil {
				return err
			}
			row := item.RecordRow
			if len(rows) == limit && compareCursor(rowCursor(row), rowCursor(rows[0])) <= 0 {
				break
			}
			if request.matchesRow(row.Kind, row.Time, row.Traffic, request.HTTPRule == "" || slices.Contains(item.rules, request.HTTPRule)) {
				rows.include(row, limit)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(rows, func(a, b RecordRow) int { return compareCursor(rowCursor(b), rowCursor(a)) })
	for index := range rows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		row := &rows[index]
		if row.Kind == "nota" {
			edits, err := s.localEdits(row.ID)
			if err != nil {
				return nil, err
			}
			if len(edits) > 0 {
				current := edits[len(edits)-1]
				row.Title, row.Source = clipRow(current.Title, 240), clipRow(current.Source, 360)
			}
		}
		if request.Kind != "http" {
			row.Traffic, row.SignalCount = nil, 0
		} else if row.Traffic != nil {
			copy := *row.Traffic
			row.Traffic = &copy
		}
	}
	return rows, nil
}
