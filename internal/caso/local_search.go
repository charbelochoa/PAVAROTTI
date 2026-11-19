package caso

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const maxLocalSearchText = 16 << 10

func (record Record) searchFields(yield func(string) bool) {
	if !yield(record.ID) {
		return
	}
	for field := range record.evidenceSearchFields {
		if !yield(field) {
			return
		}
	}
	for field := range record.metadataSearchFields {
		if !yield(field) {
			return
		}
	}
}

func (record Record) evidenceSearchFields(yield func(string) bool) {
	for field := range record.dependencySearchFields {
		if !yield(field) {
			return
		}
	}
	for _, field := range [...]string{record.Source, record.SourceID, record.Details} {
		if !yield(field) {
			return
		}
	}
}

func (record Record) metadataSearchFields(yield func(string) bool) {
	for _, field := range [...]string{record.Kind, record.Time, record.Title, record.SHA256} {
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

func localSearchText(fields func(func(string) bool)) (string, bool) {
	var document strings.Builder
	for field := range fields {
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

func decodeSearchRows(key string, data []byte) ([]localPageEntry, int, error) {
	records, err := decodeBatch(key, data)
	if err != nil {
		return nil, 0, err
	}
	rows := make([]localPageEntry, 0, len(records))
	metadata := make(map[string]string)
	weight := 0
	for _, record := range records {
		entry := localPageEntry{RecordRow: RecordRow{Kind: record.Kind, Time: record.Time, Title: record.Title,
			Source: record.Source, SourceID: record.SourceID, Traffic: record.Traffic, SignalCount: len(record.Signals)}}
		if record.Traffic != nil {
			for _, finding := range record.HTTPFindings {
				entry.rules = append(entry.rules, finding.Rule)
			}
		}
		entry.document, entry.partial = localSearchText(record.evidenceSearchFields)
		meta, partial := localSearchText(record.metadataSearchFields)
		entry.partial = entry.partial || partial
		shared, exists := metadata[meta]
		if !exists {
			shared = strings.Clone(meta)
			metadata[shared] = shared
			weight += len(shared)
		}
		entry.searchMetadata = shared
		rows = append(rows, entry)
	}
	return rows, weight, nil
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
	if strings.Contains(item.document, term) || strings.Contains(item.searchMetadata, term) || matchesPageID(key, item.ID, term) {
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

func matchesPageID(key, ordinal, term string) bool {
	if strings.Contains(key, term) || strings.Contains(ordinal, term) {
		return true
	}
	prefix, suffix, crosses := strings.Cut(term, "-")
	return crosses && strings.HasSuffix(key, prefix) && strings.HasPrefix(ordinal, suffix)
}
