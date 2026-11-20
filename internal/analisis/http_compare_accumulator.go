package analisis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"time"
)

type httpComparisonSource struct {
	stamp time.Time
	id    string
	data  []byte
}

type httpComparisonAccumulator struct {
	sources  []httpComparisonSource
	bytes    int
	baseline HTTPWindowStats
	current  HTTPWindowStats
	groups   map[httpRowKey]*httpComparisonGroup
}

type httpComparisonGroup struct {
	metric   httpMetric
	newest   int
	baseline httpRankedTally
	current  httpRankedTally
}

type httpRankedTally struct {
	count    int
	evidence []httpRankedEvidence
}

type httpRankedEvidence struct {
	source int
	ref    HTTPComparisonEvidence
}

func (comparison *httpComparisonAccumulator) add(ctx context.Context, stamp time.Time, input httpComparisonInput) error {
	data, err := json.Marshal(input)
	if err != nil {
		return err
	}
	comparison.bytes += len(data) + 1
	if comparison.bytes > SnapshotByteLimit {
		return ErrSnapshotBytes
	}
	index := len(comparison.sources)
	comparison.sources = append(comparison.sources, httpComparisonSource{stamp: stamp, id: input.Ref.ID, data: data})
	if input.Baseline {
		comparison.baseline.count(input)
	}
	if input.Current {
		comparison.current.count(input)
	}
	comparison.tally(index, input.Category, input)
	for _, signal := range input.Signals {
		if err := ctx.Err(); err != nil {
			return err
		}
		comparison.tally(index, signal, input)
	}
	return nil
}

func (comparison *httpComparisonAccumulator) tally(index int, metric httpMetric, input httpComparisonInput) {
	group := comparison.groups[metric.httpRowKey]
	if group == nil {
		group = &httpComparisonGroup{metric: metric, newest: index}
		comparison.groups[metric.httpRowKey] = group
	} else if compareHTTPSource(comparison.sources[index], comparison.sources[group.newest]) < 0 {
		group.metric.Label, group.newest = metric.Label, index
	}
	ref := input.Ref
	if metric.Kind == "rule" {
		ref.HTTPRule = metric.Code
	}
	if input.Baseline {
		comparison.rank(&group.baseline, index, ref)
	}
	if input.Current {
		comparison.rank(&group.current, index, ref)
	}
}

func (comparison *httpComparisonAccumulator) rank(tally *httpRankedTally, index int, ref HTTPComparisonEvidence) {
	tally.count++
	position := len(tally.evidence)
	for position > 0 && compareHTTPSource(comparison.sources[index], comparison.sources[tally.evidence[position-1].source]) < 0 {
		position--
	}
	if position == referenceLimit {
		return
	}
	if len(tally.evidence) == referenceLimit {
		tally.evidence = tally.evidence[:referenceLimit-1]
	}
	tally.evidence = slices.Insert(tally.evidence, position, httpRankedEvidence{source: index, ref: ref})
}

func compareHTTPSource(a, b httpComparisonSource) int {
	if order := b.stamp.Compare(a.stamp); order != 0 {
		return order
	}
	return strings.Compare(a.id, b.id)
}

func (comparison *httpComparisonAccumulator) finish(ctx context.Context, criteria HTTPCompareCriteria) (HTTPComparison, error) {
	if err := ctx.Err(); err != nil {
		return HTTPComparison{}, err
	}
	schema := HTTPComparisonSchema
	if len(comparison.sources) > RecordLimit {
		schema = HTTPComparisonWideSchema
	}
	hash := sha256.New()
	encoder := json.NewEncoder(hash)
	if err := encoder.Encode(schema); err != nil {
		return HTTPComparison{}, err
	}
	if err := encoder.Encode(criteria); err != nil {
		return HTTPComparison{}, err
	}
	slices.SortFunc(comparison.sources, compareHTTPSource)
	newline := []byte{'\n'}
	for _, source := range comparison.sources {
		if err := ctx.Err(); err != nil {
			return HTTPComparison{}, err
		}
		_, _ = hash.Write(source.data)
		_, _ = hash.Write(newline)
	}
	groups := slices.Collect(maps.Values(comparison.groups))
	slices.SortFunc(groups, compareHTTPGroups)
	rows := make([]HTTPCompareRow, 0, min(groupLimit, len(groups)))
	for _, group := range groups[:cap(rows)] {
		rows = append(rows, HTTPCompareRow{Kind: group.metric.Kind, Code: group.metric.Code, Label: group.metric.Label,
			Baseline: group.baseline.result(), Current: group.current.result()})
	}
	if err := ctx.Err(); err != nil {
		return HTTPComparison{}, err
	}
	return HTTPComparison{Schema: schema, InputSHA256: hex.EncodeToString(hash.Sum(nil)), Criteria: criteria,
		Baseline: comparison.baseline, Current: comparison.current, Rows: rows, OmittedRows: max(0, len(groups)-groupLimit)}, nil
}

func (tally httpRankedTally) result() HTTPTally {
	result := HTTPTally{Count: tally.count}
	if len(tally.evidence) > 0 {
		result.Evidence = make([]HTTPComparisonEvidence, len(tally.evidence))
		for index, item := range tally.evidence {
			result.Evidence[index] = item.ref
		}
	}
	return result
}

func compareHTTPGroups(a, b *httpComparisonGroup) int {
	kinds := [...]string{"status", "transport", "unknown", "rule", "legacy"}
	if order := slices.Index(kinds[:], a.metric.Kind) - slices.Index(kinds[:], b.metric.Kind); order != 0 {
		return order
	}
	if a.metric.Kind == "rule" || a.metric.Kind == "legacy" {
		if count := b.baseline.count + b.current.count - a.baseline.count - a.current.count; count != 0 {
			return count
		}
	}
	return strings.Compare(a.metric.Code, b.metric.Code)
}
