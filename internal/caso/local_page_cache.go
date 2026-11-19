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
	text    bool
}

type localPageEntry struct {
	RecordRow
	rules    []string
	document string
	partial  bool
}

func (cache *localPageCache) lookup(key string, info os.FileInfo, text bool) ([]localPageEntry, bool) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	entry, ok := cache.batches[key]
	return entry.rows, ok && (!text || entry.text) && entry.size == info.Size() && entry.updated.Equal(info.ModTime())
}

func (cache *localPageCache) remember(key string, info os.FileInfo, rows []localPageEntry, weight int, text bool) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	old := cache.batches[key]
	if weight > maxLocalPageCacheBytes-cache.weight+old.weight {
		return
	}
	if cache.batches == nil {
		cache.batches = make(map[string]localPageBatch)
	}
	cache.batches[key] = localPageBatch{updated: info.ModTime(), size: info.Size(), weight: weight, rows: rows, text: text}
	cache.weight += weight - old.weight
}

func (s *Store) localPageBatch(key string, file os.DirEntry, text bool) ([]localPageEntry, error) {
	info, err := file.Info()
	if err != nil {
		return nil, err
	}
	if rows, ok := s.pageCache.lookup(key, info, text); ok {
		return rows, nil
	}
	data, err := os.ReadFile(filepath.Join(s.path, file.Name()))
	if err != nil {
		return nil, err
	}
	var rows []localPageEntry
	if text {
		rows, err = decodeSearchRows(key, data)
	} else {
		rows, err = decodePageRows(data)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file.Name(), err)
	}
	weight := 256
	for index := range rows {
		row := &rows[index]
		row.ID = strconv.Itoa(index + 1)
		row.Title = compactPageText(row.Title, 240)
		row.Source = compactPageText(row.Source, 360)
		if row.Kind == "binario" {
			row.SourceID = compactPageText(row.SourceID, 160)
		} else {
			row.SourceID = ""
		}
		weight += 184 + len(row.ID) + len(row.Kind) + len(row.Time) + len(row.Title) + len(row.Source) + len(row.SourceID) + len(row.document)
		if row.Traffic != nil {
			weight += 64 + len(row.Traffic.Method) + len(row.Traffic.Type)
		}
		for _, rule := range row.rules {
			weight += 16 + len(rule)
		}
	}
	slices.SortFunc(rows, func(a, b localPageEntry) int {
		return compareCursor(rowCursor(b.RecordRow), rowCursor(a.RecordRow))
	})
	s.pageCache.remember(key, info, rows, weight, text)
	return rows, nil
}

func decodePageRows(data []byte) ([]localPageEntry, error) {
	var batch []struct {
		RecordRow
		Signals []string `json:"signals"`
		Rules   []struct {
			Rule string `json:"rule"`
		} `json:"http_findings"`
	}
	if err := json.Unmarshal(data, &batch); err != nil {
		return nil, err
	}
	rows := make([]localPageEntry, len(batch))
	for index, item := range batch {
		row := item.RecordRow
		row.SignalCount = len(item.Signals)
		entry := localPageEntry{RecordRow: row}
		if row.Traffic != nil {
			for _, finding := range item.Rules {
				entry.rules = append(entry.rules, finding.Rule)
			}
		}
		rows[index] = entry
	}
	return rows, nil
}

func compactPageText(text string, limit int) string {
	clipped := clipRow(text, limit)
	if len(clipped) == len(text) {
		return text
	}
	return strings.Clone(clipped)
}

func compareBatchPageRow(row RecordRow, key string, cursor pageCursor) int {
	if order := strings.Compare(strings.TrimSuffix(row.Time, "Z"), cursor.Stamp); order != 0 {
		return order
	}
	batch, ordinal, _ := strings.Cut(cursor.ID, "-")
	if order := strings.Compare(key, batch); order != 0 {
		return order
	}
	return strings.Compare(row.ID, ordinal)
}

func (s *Store) indexedLocalPage(ctx context.Context, request PageRequest, after pageCursor, limit int) ([]RecordRow, error) {
	unlock, err := s.lockContext(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	rows := make(rowHeap, 0, limit)
	term := strings.ToLower(request.Search)
	err = s.walkLocalBatches(ctx, func(key string, entry os.DirEntry) error {
		batch, err := s.localPageBatch(key, entry, term != "")
		if err != nil {
			return err
		}
		first := 0
		if after.ID != "" {
			first = sort.Search(len(batch), func(index int) bool {
				return compareBatchPageRow(batch[index].RecordRow, key, after) < 0
			})
		}
		var full []Record
		for _, item := range batch[first:] {
			if err := ctx.Err(); err != nil {
				return err
			}
			row := item.RecordRow
			if len(rows) == limit && compareBatchPageRow(row, key, rowCursor(rows[0])) <= 0 {
				break
			}
			if !request.matchesRow(row.Kind, row.Time, row.Traffic, request.HTTPRule == "" || slices.Contains(item.rules, request.HTTPRule)) {
				continue
			}
			if term != "" {
				matched, err := s.localSearchMatch(item, key, entry.Name(), term, &full)
				if err != nil {
					return err
				}
				if !matched {
					continue
				}
			}
			row.ID = key + "-" + row.ID
			rows.include(row, limit)
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
