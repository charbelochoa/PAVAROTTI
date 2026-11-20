package analisis

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"

	"pavarotti/internal/caso"
)

var ErrAssetQuery = errors.New("consulta de activos inválida")

type AssetKey = caso.AssetKey

type AssetQuery struct {
	AssetKey
	Search string
	After  string
	Limit  int
}

type AssetRow struct {
	AssetKey
	Count      int `json:"count"`
	Indicators int `json:"indicators"`
}

type AssetPage struct {
	Rows []AssetRow `json:"rows"`
	Next string     `json:"next,omitempty"`
}

type AssetReference struct {
	Evidence
	Role    string `json:"role"`
	Network string `json:"network,omitempty"`
}

type AssetDetail struct {
	AssetRow
	Coverage int              `json:"coverage,omitempty"`
	Rows     []AssetReference `json:"rows"`
	Next     string           `json:"next,omitempty"`
}

func ListAssets(ctx context.Context, store *caso.Store, query AssetQuery) (AssetPage, error) {
	limit, ok := assetPageSize(query.Limit)
	term := strings.ToLower(strings.TrimSpace(query.Search))
	if !ok || query.Value != "" || (query.Type != "" && !assetType(query.Type)) || len(term) > 253 || strings.ContainsRune(term, 0) {
		return AssetPage{}, ErrAssetQuery
	}
	var after AssetKey
	if query.After != "" {
		kind, value, _ := strings.Cut(query.After, "/")
		key, valid := caso.NormalizeAsset(AssetKey{Type: kind, Value: value})
		if !valid || key.Cursor() != query.After || (query.Type != "" && key.Type != query.Type) {
			return AssetPage{}, ErrAssetQuery
		}
		after = key
	}
	rows := make([]AssetRow, 0, limit+1)
	err := store.Walk(ctx, func(record caso.Record) error {
		var network caso.AssetNetwork
		if query.Type == "" || query.Type == "red" {
			network = caso.RecordNetwork(record)
		}
		caso.RecordAssets(record, network, query.Type, func(key AssetKey, role string) {
			if (query.Type != "" && key.Type != query.Type) || (term != "" && !strings.Contains(key.Value, term)) ||
				(after.Type != "" && compareAssetKeys(key, after) <= 0) {
				return
			}
			index, found := slices.BinarySearchFunc(rows, key, func(row AssetRow, key AssetKey) int {
				return compareAssetKeys(row.AssetKey, key)
			})
			if found {
				rows[index].add(role)
				return
			}
			if index == cap(rows) {
				return
			}
			if len(rows) == cap(rows) {
				rows = rows[:len(rows)-1]
			}
			next := AssetRow{AssetKey: key}
			next.add(role)
			rows = slices.Insert(rows, index, next)
		})
		return nil
	})
	if err != nil {
		return AssetPage{}, err
	}
	page := AssetPage{Rows: rows[:min(len(rows), limit)]}
	if len(rows) > limit {
		page.Next = page.Rows[limit-1].Cursor()
	}
	return page, nil
}

func compareAssetKeys(a, b AssetKey) int {
	if order := strings.Compare(a.Type, b.Type); order != 0 {
		return order
	}
	return strings.Compare(a.Value, b.Value)
}

func DescribeAsset(ctx context.Context, store *caso.Store, query AssetQuery) (AssetDetail, error) {
	limit, ok := assetPageSize(query.Limit)
	key, valid := caso.NormalizeAsset(query.AssetKey)
	if !ok || !valid || query.Search != "" || len(query.After) > 85 {
		return AssetDetail{}, ErrAssetQuery
	}
	detail := AssetDetail{AssetRow: AssetRow{AssetKey: key}}
	var after assetSourceCursor
	if query.After != "" {
		original, err := store.RecordRevision(ctx, query.After, 1)
		if err != nil && !errors.Is(err, caso.ErrNotFound) {
			return AssetDetail{}, err
		}
		if err == nil {
			after = assetSourcePosition(original)
		}
	}
	afterFound := query.After == ""
	rows := make([]orderedAssetSource, 0, limit+1)
	address, _ := netip.ParseAddr(key.Value)
	err := store.Walk(ctx, func(record caso.Record) error {
		role, network := assetSource(record, key, address)
		switch role {
		case "":
			return nil
		case "cobertura":
			detail.Coverage++
		default:
			detail.add(role)
		}
		position := assetSourcePosition(record)
		if query.After != "" {
			order := compareAssetSourcePositions(position, after)
			afterFound = afterFound || order == 0
			if after.id == "" || order <= 0 {
				return nil
			}
		}
		index, _ := slices.BinarySearchFunc(rows, position, func(row orderedAssetSource, key assetSourceCursor) int {
			return compareAssetSourcePositions(row.position, key)
		})
		if index == cap(rows) {
			return nil
		}
		if len(rows) == cap(rows) {
			rows = rows[:len(rows)-1]
		}
		row := AssetReference{Evidence: reference(record), Role: role, Network: network}
		rows = slices.Insert(rows, index, orderedAssetSource{position: position, source: row})
		return nil
	})
	if err != nil {
		return AssetDetail{}, err
	}
	if detail.Count+detail.Coverage == 0 {
		return AssetDetail{}, caso.ErrNotFound
	}
	if !afterFound {
		return AssetDetail{}, ErrAssetQuery
	}
	detail.Rows = make([]AssetReference, min(len(rows), limit))
	for index := range detail.Rows {
		detail.Rows[index] = rows[index].source
	}
	if len(rows) > limit {
		detail.Next = detail.Rows[limit-1].ID
	}
	return detail, nil
}

type assetSourceCursor struct {
	stamp time.Time
	id    string
}

type orderedAssetSource struct {
	position assetSourceCursor
	source   AssetReference
}

func assetSourcePosition(record caso.Record) assetSourceCursor {
	stamp, _ := time.Parse(time.RFC3339Nano, clip(record.Time, 48))
	return assetSourceCursor{stamp: stamp, id: record.ID}
}

func compareAssetSourcePositions(a, b assetSourceCursor) int {
	if order := b.stamp.Compare(a.stamp); order != 0 {
		return order
	}
	return strings.Compare(a.id, b.id)
}

func assetSource(record caso.Record, key AssetKey, address netip.Addr) (string, string) {
	var network caso.AssetNetwork
	if key.Type == "red" || address.IsValid() {
		network = caso.RecordNetwork(record)
	}
	var role string
	caso.RecordAssets(record, network, key.Type, func(candidate AssetKey, current string) {
		if candidate == key && role == "" {
			role = current
		}
	})
	if role == "" && address.IsValid() && network.Contains(address) {
		return "cobertura", network.Value
	}
	return role, ""
}

func walkEvidence(ctx context.Context, store *caso.Store, visit func(caso.Record)) error {
	count := 0
	return store.Walk(ctx, func(record caso.Record) error {
		if count == RecordLimit {
			return ErrLimit
		}
		count++
		visit(record)
		return nil
	})
}

func assetPageSize(limit int) (int, bool) {
	if limit == 0 {
		return caso.DefaultPageSize, true
	}
	return limit, limit > 0 && limit <= 100
}

func assetType(kind string) bool {
	switch kind {
	case "dominio", "ipv4", "ipv6", "red", "md5", "sha1", "sha256":
		return true
	}
	return false
}

func (row *AssetRow) add(role string) {
	row.Count++
	if role == "indicador" {
		row.Indicators++
	}
}
