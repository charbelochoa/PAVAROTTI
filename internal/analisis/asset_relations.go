package analisis

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"pavarotti/internal/caso"
)

const (
	AssetRelationsSchema = "pavarotti.asset-relations.v1"
	assetRelationLimit   = 50_000
)

var ErrAssetRelationLimit = errors.New("la consulta supera 50000 relaciones distintas, acota el periodo")

type AssetRelationCriteria struct {
	AssetKey
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

type AssetRelation struct {
	AssetKey
	Kind      string     `json:"kind"`
	Direction string     `json:"direction"`
	Count     int        `json:"count"`
	First     string     `json:"first,omitempty"`
	Last      string     `json:"last,omitempty"`
	Sources   []Evidence `json:"sources"`
}

type AssetRelationsReport struct {
	Schema      string                `json:"schema"`
	Criteria    AssetRelationCriteria `json:"criteria"`
	Records     int                   `json:"records"`
	Rows        []AssetRelation       `json:"rows"`
	OmittedRows int                   `json:"omitted_rows"`
}

type assetRelationKey struct {
	asset     AssetKey
	kind      string
	direction string
}

type relationCitation struct {
	position assetSourceCursor
	evidence Evidence
}

type relationAggregate struct {
	count       int
	first, last time.Time
	citations   []relationCitation
}

func RelateAsset(ctx context.Context, store *caso.Store, criteria AssetRelationCriteria) (AssetRelationsReport, error) {
	anchor, valid := caso.NormalizeAsset(criteria.AssetKey)
	if !valid {
		return AssetRelationsReport{}, ErrAssetQuery
	}
	criteria.AssetKey = anchor
	filter := caso.EvidenceFilter{}
	if criteria.From != "" || criteria.To != "" {
		period, err := parseUTCPeriod(criteria.From, criteria.To)
		if err != nil {
			return AssetRelationsReport{}, fmt.Errorf("%w: %w", ErrAssetQuery, err)
		}
		filter.Periods = []caso.EvidencePeriod{period}
	}
	report := AssetRelationsReport{Schema: AssetRelationsSchema, Criteria: criteria}
	address, _ := netip.ParseAddr(anchor.Value)
	var network caso.AssetNetwork
	if anchor.Type == "red" {
		network = caso.ParseAssetNetwork(anchor.Value)
	}
	groups := make(map[assetRelationKey]*relationAggregate)
	err := store.WalkFiltered(ctx, filter, func(record caso.Record) error {
		var ref relationCitation
		var limitReached bool
		recordAssetRelations(record, anchor, address, network, func(key assetRelationKey) {
			group := groups[key]
			if group == nil {
				if len(groups) == assetRelationLimit {
					limitReached = true
					return
				}
				group = &relationAggregate{}
				groups[key] = group
			}
			if ref.position.id == "" {
				ref = relationCitation{position: assetSourcePosition(record), evidence: reference(record)}
				report.Records++
			}
			group.add(ref)
		})
		if limitReached {
			return ErrAssetRelationLimit
		}
		return nil
	})
	if err != nil {
		return AssetRelationsReport{}, err
	}
	keys := make([]assetRelationKey, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b assetRelationKey) int {
		if order := groups[b].count - groups[a].count; order != 0 {
			return order
		}
		if order := compareAssetKeys(a.asset, b.asset); order != 0 {
			return order
		}
		if order := strings.Compare(a.kind, b.kind); order != 0 {
			return order
		}
		return strings.Compare(a.direction, b.direction)
	})
	visible := min(len(keys), groupLimit)
	report.OmittedRows = len(keys) - visible
	report.Rows = make([]AssetRelation, 0, visible)
	for _, key := range keys[:visible] {
		group := groups[key]
		row := AssetRelation{AssetKey: key.asset, Kind: key.kind, Direction: key.direction, Count: group.count,
			Sources: make([]Evidence, 0, len(group.citations))}
		if !group.first.IsZero() {
			row.First = group.first.UTC().Format(time.RFC3339Nano)
			row.Last = group.last.UTC().Format(time.RFC3339Nano)
		}
		for _, citation := range group.citations {
			row.Sources = append(row.Sources, citation.evidence)
		}
		report.Rows = append(report.Rows, row)
	}
	return report, ctx.Err()
}

func (group *relationAggregate) add(ref relationCitation) {
	group.count++
	stamp := ref.position.stamp
	if !stamp.IsZero() {
		if group.first.IsZero() || stamp.Before(group.first) {
			group.first = stamp
		}
		if group.last.IsZero() || stamp.After(group.last) {
			group.last = stamp
		}
	}
	index, _ := slices.BinarySearchFunc(group.citations, ref.position, func(item relationCitation, key assetSourceCursor) int {
		return compareAssetSourcePositions(item.position, key)
	})
	if index == referenceLimit {
		return
	}
	if len(group.citations) == referenceLimit {
		group.citations = group.citations[:referenceLimit-1]
	}
	group.citations = slices.Insert(group.citations, index, ref)
}
