package analisis

import (
	"context"
	"encoding/hex"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"

	"pavarotti/internal/caso"
)

var ErrAssetQuery = errors.New("consulta de activos inválida")

type AssetKey struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

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
	if query.After != "" {
		kind, value, _ := strings.Cut(query.After, "/")
		key, valid := normalizeAsset(AssetKey{Type: kind, Value: value})
		if !valid || key.cursor() != query.After || (query.Type != "" && key.Type != query.Type) {
			return AssetPage{}, ErrAssetQuery
		}
	}
	rows := make(map[AssetKey]AssetRow)
	err := walkEvidence(ctx, store, func(record caso.Record) {
		recordAssets(record, recordNetwork(record), func(key AssetKey, role string) {
			if (query.Type != "" && key.Type != query.Type) || (term != "" && !strings.Contains(key.Value, term)) ||
				(query.After != "" && key.cursor() <= query.After) {
				return
			}
			row := rows[key]
			row.AssetKey = key
			row.add(role)
			rows[key] = row
		})
	})
	if err != nil {
		return AssetPage{}, err
	}
	ordered := make([]AssetRow, 0, len(rows))
	for _, row := range rows {
		ordered = append(ordered, row)
	}
	slices.SortFunc(ordered, func(a, b AssetRow) int {
		if order := strings.Compare(a.Type, b.Type); order != 0 {
			return order
		}
		return strings.Compare(a.Value, b.Value)
	})
	page := AssetPage{Rows: ordered[:min(len(ordered), limit)]}
	if len(ordered) > limit {
		page.Next = page.Rows[limit-1].cursor()
	}
	return page, nil
}

func DescribeAsset(ctx context.Context, store *caso.Store, query AssetQuery) (AssetDetail, error) {
	limit, ok := assetPageSize(query.Limit)
	key, valid := normalizeAsset(query.AssetKey)
	if !ok || !valid || query.Search != "" || len(query.After) > 85 {
		return AssetDetail{}, ErrAssetQuery
	}
	detail := AssetDetail{AssetRow: AssetRow{AssetKey: key}}
	rows := make([]AssetReference, 0)
	address, _ := netip.ParseAddr(key.Value)
	err := walkEvidence(ctx, store, func(record caso.Record) {
		role, network := assetSource(record, key, address)
		switch role {
		case "":
			return
		case "cobertura":
			detail.Coverage++
		default:
			detail.add(role)
		}
		rows = append(rows, AssetReference{Evidence: reference(record), Role: role, Network: network})
	})
	if err != nil {
		return AssetDetail{}, err
	}
	if len(rows) == 0 {
		return AssetDetail{}, caso.ErrNotFound
	}
	slices.SortFunc(rows, func(a, b AssetReference) int {
		if a.Time != b.Time {
			left, _ := time.Parse(time.RFC3339Nano, a.Time)
			right, _ := time.Parse(time.RFC3339Nano, b.Time)
			if order := right.Compare(left); order != 0 {
				return order
			}
		}
		return strings.Compare(a.ID, b.ID)
	})
	if query.After != "" {
		index := slices.IndexFunc(rows, func(row AssetReference) bool { return row.ID == query.After })
		if index == -1 {
			return AssetDetail{}, ErrAssetQuery
		}
		rows = rows[index+1:]
	}
	detail.Rows = rows[:min(len(rows), limit)]
	if len(rows) > limit {
		detail.Next = detail.Rows[limit-1].ID
	}
	return detail, nil
}

func assetSource(record caso.Record, key AssetKey, address netip.Addr) (string, string) {
	network := recordNetwork(record)
	var role string
	recordAssets(record, network, func(candidate AssetKey, current string) {
		if candidate == key && role == "" {
			role = current
		}
	})
	if role == "" && address.IsValid() && network.contains(address) {
		return "cobertura", network.value
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

func recordAssets(record caso.Record, network assetNetwork, visit func(AssetKey, string)) {
	if item := record.Indicator; item != nil {
		if key, valid := normalizeAsset(AssetKey(*item)); valid {
			visit(key, "indicador")
		}
		return
	}
	if record.Kind == "binario" {
		if value := digest(record.SHA256); value != "" {
			visit(AssetKey{Type: "sha256", Value: value}, "muestra")
		}
		return
	}
	if record.Traffic != nil {
		if host := networkHost(record.Source); host != "" {
			visit(hostAsset(host), "observación")
		}
		return
	}
	var role string
	switch record.Kind {
	case "dns":
		role = "observación"
	case "rdap":
		role = "registro"
	case "stix":
		role = "declaración"
	case "hallazgo", "nota":
		role = "referencia"
	default:
		return
	}
	if network.value != "" {
		visit(AssetKey{Type: "red", Value: network.value}, role)
	}
	if record.Kind == "stix" {
		for _, item := range record.FileHashes {
			if key, valid := normalizeAsset(AssetKey(item)); valid {
				visit(key, "huella declarada")
			}
		}
	}
	for _, host := range sourceHosts(record.Source, record.Kind == "rdap") {
		visit(hostAsset(host), role)
	}
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

func normalizeAsset(key AssetKey) (AssetKey, bool) {
	if len(key.Value) > 254 {
		return AssetKey{}, false
	}
	value := strings.ToLower(strings.TrimSpace(key.Value))
	switch key.Type {
	case "dominio", "ipv4", "ipv6":
		kind := hostAsset(value)
		if kind.Type == "dominio" {
			kind.Value = namedHost(value)
		}
		return kind, kind.Type == key.Type && kind.Value != ""
	case "md5", "sha1", "sha256":
		if len(value) == map[string]int{"md5": 32, "sha1": 40, "sha256": 64}[key.Type] {
			if _, err := hex.DecodeString(value); err == nil {
				return AssetKey{Type: key.Type, Value: value}, true
			}
		}
	case "red":
		network := parseAssetNetwork(value)
		return AssetKey{Type: key.Type, Value: network.value}, network.value != ""
	}
	return AssetKey{}, false
}

func hostAsset(value string) AssetKey {
	if address, err := netip.ParseAddr(value); err == nil && address.Zone() == "" {
		address = address.Unmap()
		if address.Is4() {
			return AssetKey{Type: "ipv4", Value: address.String()}
		}
		return AssetKey{Type: "ipv6", Value: address.String()}
	}
	return AssetKey{Type: "dominio", Value: value}
}

func (key AssetKey) cursor() string { return key.Type + "/" + key.Value }

func (row *AssetRow) add(role string) {
	row.Count++
	if role == "indicador" {
		row.Indicators++
	}
}
