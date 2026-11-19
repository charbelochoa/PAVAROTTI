package caso

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const maxLocalSearchText = 16 << 10

func (record Record) searchFields(yield func(string) bool) {
	for field := range record.dependencySearchFields {
		if !yield(field) {
			return
		}
	}
	for _, field := range [...]string{record.ID, record.Kind, record.Time, record.Title, record.Source,
		record.SourceID, record.SHA256, record.Details} {
		if !yield(field) {
			return
		}
	}
	for _, signal := range record.Signals {
		if !yield(signal) {
			return
		}
	}
	if traffic := record.Traffic; traffic != nil {
		for _, field := range [...]string{traffic.Method, traffic.Type, strconv.Itoa(traffic.Status),
			strconv.FormatInt(traffic.Millis, 10), strconv.FormatInt(traffic.Bucket, 10)} {
			if !yield(field) {
				return
			}
		}
	}
}

func localSearchText(record Record) (string, bool) {
	var document strings.Builder
	for field := range record.searchFields {
		if field == "" {
			continue
		}
		field = strings.ToLower(field)
		if document.Len()+len(field)+1 > maxLocalSearchText {
			return document.String(), true
		}
		document.WriteString(field)
		document.WriteByte(0)
	}
	return document.String(), false
}

func decodeSearchRows(key string, data []byte) ([]localPageEntry, error) {
	records, err := decodeBatch(key, data)
	if err != nil {
		return nil, err
	}
	rows := make([]localPageEntry, 0, len(records))
	for _, record := range records {
		entry := localPageEntry{RecordRow: RecordRow{Kind: record.Kind, Time: record.Time, Title: record.Title,
			Source: record.Source, SourceID: record.SourceID, Traffic: record.Traffic, SignalCount: len(record.Signals)}}
		if record.Traffic != nil {
			for _, finding := range record.HTTPFindings {
				entry.rules = append(entry.rules, finding.Rule)
			}
		}
		entry.document, entry.partial = localSearchText(record)
		rows = append(rows, entry)
	}
	return rows, nil
}

func (s *Store) localSearchMatch(item localPageEntry, key, filename, term string, full *[]Record) (bool, error) {
	if item.Kind == "nota" {
		edits, err := s.localEdits(key + "-" + item.ID)
		if err != nil {
			return false, err
		}
		if len(edits) != 0 {
			return matches(edits[len(edits)-1], term), nil
		}
	}
	if strings.Contains(item.document, term) {
		return true, nil
	}
	if !item.partial {
		return false, nil
	}
	if *full == nil {
		data, err := os.ReadFile(filepath.Join(s.path, filename))
		if err != nil {
			return false, err
		}
		*full, err = decodeBatch(key, data)
		if err != nil {
			return false, err
		}
	}
	ordinal, _ := strconv.Atoi(item.ID)
	return matches((*full)[ordinal-1], term), nil
}
