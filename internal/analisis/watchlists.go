package analisis

import (
	"context"
	"net/netip"

	"pavarotti/internal/caso"
)

type WatchlistReview struct {
	Name string           `json:"name"`
	Rows []WatchlistAsset `json:"rows"`
}

type WatchlistAsset struct {
	AssetRow
	Coverage int             `json:"coverage"`
	Latest   *AssetReference `json:"latest,omitempty"`
}

func ChangeWatchlist(ctx context.Context, store *caso.Store, name string, action caso.WatchAction, asset AssetKey) (bool, error) {
	if action == caso.WatchAdd || action == caso.WatchRemove {
		var valid bool
		asset, valid = normalizeAsset(asset)
		if !valid {
			return false, ErrAssetQuery
		}
	}
	return store.ChangeWatchlist(ctx, name, action, caso.Indicator(asset))
}

func ReviewWatchlist(ctx context.Context, store *caso.Store, name string) (WatchlistReview, error) {
	list, err := store.Watchlist(ctx, name)
	if err != nil {
		return WatchlistReview{}, err
	}
	review := WatchlistReview{Name: list.Name, Rows: make([]WatchlistAsset, len(list.Assets))}
	if len(list.Assets) == 0 {
		return review, nil
	}
	positions := make(map[AssetKey]int, len(list.Assets))
	type watchedIP struct {
		position int
		address  netip.Addr
	}
	var ips []watchedIP
	for index, asset := range list.Assets {
		key, valid := normalizeAsset(AssetKey(asset))
		if !valid || key != AssetKey(asset) {
			return WatchlistReview{}, caso.ErrWatchlist
		}
		positions[key] = index
		review.Rows[index].AssetKey = key
		if address, err := netip.ParseAddr(key.Value); err == nil {
			ips = append(ips, watchedIP{position: index, address: address})
		}
	}
	direct := make([]string, len(list.Assets))
	latest := make([]assetSourceCursor, len(list.Assets))
	err = store.Walk(ctx, func(record caso.Record) error {
		network := recordNetwork(record)
		save := func(index int, role, coverage string) {
			row := &review.Rows[index]
			if role == "cobertura" {
				row.Coverage++
			} else {
				row.add(role)
				direct[index] = record.ID
			}
			position := assetSourcePosition(record)
			if row.Latest == nil || compareAssetSourcePositions(position, latest[index]) < 0 {
				latest[index] = position
				row.Latest = &AssetReference{Evidence: reference(record), Role: role, Network: coverage}
			}
		}
		recordAssets(record, network, "", func(key AssetKey, role string) {
			if index, exists := positions[key]; exists && direct[index] != record.ID {
				save(index, role, "")
			}
		})
		if network.value != "" {
			for _, ip := range ips {
				if direct[ip.position] != record.ID && network.contains(ip.address) {
					save(ip.position, "cobertura", network.value)
				}
			}
		}
		return nil
	})
	if err != nil {
		return WatchlistReview{}, err
	}
	return review, nil
}
