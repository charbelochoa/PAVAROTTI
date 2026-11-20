package analisis

import (
	"context"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"time"

	"pavarotti/internal/caso"
)

type NetworkObservations struct {
	Network   string               `json:"network"`
	Addresses int                  `json:"addresses"`
	Records   int                  `json:"records"`
	Rows      []NetworkObservation `json:"rows"`
	Next      string               `json:"next,omitempty"`
}

type NetworkObservation struct {
	AssetKey
	Count    int        `json:"count"`
	Evidence []Evidence `json:"evidence"`
}

type assetInput struct {
	Reference AssetReference `json:"reference"`
	Addresses []netip.Addr   `json:"addresses,omitempty"`
	stamp     time.Time
}

func ListNetworkObservations(ctx context.Context, store *caso.Store, value, after string, limit int) (NetworkObservations, error) {
	key, ok := caso.NormalizeAsset(AssetKey{Type: "red", Value: value})
	pageSize, valid := assetPageSize(limit)
	var cursor netip.Addr
	network := caso.ParseAssetNetwork(key.Value)
	if !ok || !valid || len(after) > 45 {
		return NetworkObservations{}, ErrAssetQuery
	}
	if after != "" {
		var err error
		cursor, err = netip.ParseAddr(after)
		if err != nil || cursor.String() != after || cursor.Zone() != "" || !network.Contains(cursor) {
			return NetworkObservations{}, ErrAssetQuery
		}
	}
	inputs, err := collectAssetInput(ctx, store, key, nil, false)
	if err != nil {
		return NetworkObservations{}, err
	}
	rows, records := networkObservationRows(inputs)
	page := NetworkObservations{Network: key.Value, Addresses: len(rows), Records: records}
	if cursor.IsValid() {
		start, found := slices.BinarySearchFunc(rows, cursor, func(row NetworkObservation, key netip.Addr) int {
			address, _ := netip.ParseAddr(row.Value)
			return address.Compare(key)
		})
		if found {
			start++
		}
		rows = rows[start:]
	}
	page.Rows = rows[:min(pageSize, len(rows))]
	if len(rows) > pageSize {
		page.Next = page.Rows[pageSize-1].Value
	}
	return page, nil
}

func collectAssetInput(ctx context.Context, store *caso.Store, key AssetKey, period *caso.EvidencePeriod, sources bool) ([]assetInput, error) {
	network := caso.ParseAssetNetwork(key.Value)
	address, _ := netip.ParseAddr(key.Value)
	var inputs []assetInput
	filter := caso.EvidenceFilter{}
	if period != nil {
		filter.Periods = []caso.EvidencePeriod{*period}
	}
	size := 0
	err := store.WalkFiltered(ctx, filter, func(record caso.Record) error {
		var in assetInput
		if sources {
			in.Reference.Role, in.Reference.Network = assetSource(record, key, address)
		}
		if key.Type == "red" {
			in.Addresses = observedNetworkAddresses(record, network)
		}
		if in.Reference.Role == "" && len(in.Addresses) == 0 {
			return nil
		}
		if len(inputs) == RecordLimit {
			return ErrLimit
		}
		stamp, _ := time.Parse(time.RFC3339Nano, record.Time)
		in.Reference.Evidence, in.stamp = reference(record), stamp
		data, err := json.Marshal(in)
		if err != nil {
			return err
		}
		size += len(data) + 1
		if size > SnapshotByteLimit {
			return ErrSnapshotBytes
		}
		inputs = append(inputs, in)
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(inputs, func(a, b assetInput) int {
		if order := b.stamp.Compare(a.stamp); order != 0 {
			return order
		}
		return strings.Compare(a.Reference.ID, b.Reference.ID)
	})
	return inputs, ctx.Err()
}

func observedNetworkAddresses(record caso.Record, network caso.AssetNetwork) []netip.Addr {
	var hosts []string
	switch {
	case record.Indicator != nil:
		return nil
	case record.Traffic != nil:
		if record.Traffic.Status < 100 || record.Traffic.Status > 599 || record.HTTPTransportFailure() {
			return nil
		}
		hosts = []string{caso.NetworkHost(record.Source)}
	case record.Kind == "dns":
		if strings.Contains(record.SourceID, "/pregunta/") {
			return nil
		}
		if strings.Contains(record.SourceID, "/respuesta/") {
			if !strings.HasPrefix(record.Title, "A ") && !strings.HasPrefix(record.Title, "AAAA ") {
				return nil
			}
			last := strings.LastIndexByte(record.Source, ',')
			hosts = []string{caso.NetworkHost(record.Source[last+1:])}
		} else {
			hosts = observedHosts(record.Source)
		}
	}
	var addresses []netip.Addr
	for _, host := range hosts {
		address, err := netip.ParseAddr(host)
		if err == nil && network.Contains(address) {
			addresses = append(addresses, address)
		}
	}
	slices.SortFunc(addresses, netip.Addr.Compare)
	return addresses
}

func networkObservationRows(inputs []assetInput) ([]NetworkObservation, int) {
	members := make(map[netip.Addr]*NetworkObservation)
	records := 0
	for _, in := range inputs {
		if len(in.Addresses) > 0 {
			records++
		}
		for _, address := range in.Addresses {
			row := members[address]
			if row == nil {
				row = &NetworkObservation{AssetKey: caso.AssetHost(address.String())}
				members[address] = row
			}
			row.Count++
			if len(row.Evidence) < referenceLimit {
				row.Evidence = append(row.Evidence, in.Reference.Evidence)
			}
		}
	}
	ordered := make([]netip.Addr, 0, len(members))
	for address := range members {
		ordered = append(ordered, address)
	}
	slices.SortFunc(ordered, netip.Addr.Compare)
	rows := make([]NetworkObservation, 0, len(ordered))
	for _, address := range ordered {
		rows = append(rows, *members[address])
	}
	return rows, records
}
