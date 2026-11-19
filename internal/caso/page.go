package caso

import (
	"container/heap"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
)

const DefaultPageSize = 50

var ErrInvalidPage = errors.New("paginación inválida")

type PageRequest struct {
	Limit     int
	Kind      string
	Search    string
	After     string
	HTTPClass int
}

type RecordRow struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"`
	Time        string   `json:"time"`
	Title       string   `json:"title"`
	Source      string   `json:"source,omitempty"`
	Traffic     *Traffic `json:"traffic,omitempty"`
	SignalCount int      `json:"signal_count,omitempty"`
}

type Page struct {
	Rows []RecordRow `json:"rows"`
	Next string      `json:"next,omitempty"`
}

type pageCursor struct {
	Stamp string `json:"t"`
	ID    string `json:"i"`
}

func (s *Store) Page(ctx context.Context, request PageRequest) (Page, error) {
	if request.Limit == 0 {
		request.Limit = DefaultPageSize
	}
	request.Search = strings.TrimSpace(request.Search)
	if request.Limit < 1 || request.Limit > 100 || len(request.Search) > 1024 || len(request.Kind) > 64 ||
		strings.ContainsRune(request.Search, 0) || strings.ContainsRune(request.Kind, 0) ||
		(request.HTTPClass != 0 && (request.Kind != "http" || request.HTTPClass < 1 || request.HTTPClass > 5)) {
		return Page{}, ErrInvalidPage
	}
	after, err := decodeCursor(request.After)
	if err != nil {
		return Page{}, err
	}
	limit := request.Limit + 1
	var rows []RecordRow
	if s.db != nil {
		rows, err = s.postgresPage(ctx, request, after, limit)
	} else {
		rows, err = s.localPage(ctx, request, after, limit)
	}
	if err != nil {
		return Page{}, err
	}
	page := Page{Rows: rows[:min(len(rows), request.Limit)]}
	if len(rows) > request.Limit {
		value, err := json.Marshal(rowCursor(page.Rows[len(page.Rows)-1]))
		if err != nil {
			return Page{}, err
		}
		page.Next = base64.RawURLEncoding.EncodeToString(value)
	}
	return page, nil
}

func decodeCursor(raw string) (pageCursor, error) {
	var value pageCursor
	if raw == "" {
		return value, nil
	}
	if len(raw) > 1024 {
		return value, ErrInvalidPage
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || json.Unmarshal(data, &value) != nil || strings.ContainsRune(value.Stamp, 0) {
		return value, ErrInvalidPage
	}
	if _, _, valid := recordPosition(value.ID); !valid {
		return value, ErrInvalidPage
	}
	return value, nil
}

func (s *Store) localPage(ctx context.Context, request PageRequest, after pageCursor, limit int) ([]RecordRow, error) {
	rows := make(rowHeap, 0, limit)
	term := strings.ToLower(request.Search)
	err := s.walkLocal(ctx, true, func(record Record) error {
		cursor := pageCursor{Stamp: strings.TrimSuffix(record.Time, "Z"), ID: record.ID}
		if !matchesView(record, request) ||
			(after.ID != "" && compareCursor(cursor, after) >= 0) || !matches(record, term) {
			return nil
		}
		if len(rows) == limit && compareCursor(cursor, rowCursor(rows[0])) <= 0 {
			return nil
		}
		row := RecordRow{ID: record.ID, Kind: record.Kind, Time: record.Time,
			Title: clipRow(record.Title, 240), Source: clipRow(record.Source, 360)}
		if request.Kind == "http" {
			row.Traffic, row.SignalCount = record.Traffic, len(record.Signals)
		}
		if len(rows) < limit {
			heap.Push(&rows, row)
		} else {
			rows[0] = row
			heap.Fix(&rows, 0)
		}
		return nil
	})
	slices.SortFunc(rows, func(a, b RecordRow) int { return compareCursor(rowCursor(b), rowCursor(a)) })
	return rows, err
}

func matchesView(record Record, request PageRequest) bool {
	if request.Kind == "http" {
		return record.Traffic != nil && (request.HTTPClass == 0 || record.Traffic.Status/100 == request.HTTPClass)
	}
	return request.Kind == "" || request.Kind == record.Kind
}

func matches(record Record, term string) bool {
	if term == "" {
		return true
	}
	fields := []string{record.ID, record.Kind, record.Time, record.Title, record.Source, record.SourceID, record.SHA256, record.Details}
	fields = append(fields, record.Signals...)
	if record.Traffic != nil {
		fields = append(fields, record.Traffic.Method, record.Traffic.Type, strconv.Itoa(record.Traffic.Status),
			strconv.FormatInt(record.Traffic.Millis, 10), strconv.FormatInt(record.Traffic.Bucket, 10))
	}
	return slices.ContainsFunc(fields, func(field string) bool {
		return strings.Contains(strings.ToLower(field), term)
	})
}

func clipRow(text string, length int) string {
	for index := range text {
		if length == 0 {
			return text[:index]
		}
		length--
	}
	return text
}

func rowCursor(row RecordRow) pageCursor {
	return pageCursor{Stamp: strings.TrimSuffix(row.Time, "Z"), ID: row.ID}
}

func compareCursor(a, b pageCursor) int {
	if a.Stamp != b.Stamp {
		return strings.Compare(a.Stamp, b.Stamp)
	}
	return strings.Compare(a.ID, b.ID)
}

type rowHeap []RecordRow

func (h rowHeap) Len() int           { return len(h) }
func (h rowHeap) Less(i, j int) bool { return compareCursor(rowCursor(h[i]), rowCursor(h[j])) < 0 }
func (h rowHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *rowHeap) Push(item any)     { *h = append(*h, item.(RecordRow)) }
func (h *rowHeap) Pop() any {
	rows := *h
	item := rows[len(rows)-1]
	*h = rows[:len(rows)-1]
	return item
}

func (s *Store) Record(ctx context.Context, id string) (Record, error) {
	key, ordinal, valid := recordPosition(id)
	if !valid {
		return Record{}, ErrNotFound
	}
	if s.db != nil {
		return s.postgresRecord(ctx, key, ordinal)
	}
	unlock, err := s.lockContext(ctx)
	if err != nil {
		return Record{}, err
	}
	defer unlock()
	record, err := s.localRecord(key, ordinal)
	if err != nil {
		return Record{}, err
	}
	return s.latestLocal(record)
}
