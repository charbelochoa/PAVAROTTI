package caso

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxWatchlists     = 24
	maxWatchAssets    = 200
	maxWatchStateSize = 2 << 20
)

var (
	ErrWatchlist       = errors.New("indica una lista y un activo válidos")
	ErrWatchlistAbsent = errors.New("la lista de seguimiento no existe")
	ErrWatchlistLimit  = errors.New("el expediente admite 24 listas y 200 activos por lista")
	errWatchState      = errors.New("el archivo de seguimiento del expediente contiene datos inválidos")
)

type WatchAction string

const (
	WatchCreate WatchAction = "crear"
	WatchDelete WatchAction = "eliminar"
	WatchAdd    WatchAction = "agregar"
	WatchRemove WatchAction = "quitar"
)

type Watchlist struct {
	Name   string      `json:"name"`
	Assets []Indicator `json:"assets"`
}

type WatchlistSummary struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type watchState map[string][]Indicator

func (s *Store) Watchlists(ctx context.Context) ([]WatchlistSummary, error) {
	state, err := s.watchState(ctx)
	if err != nil {
		return nil, err
	}
	lists := make([]WatchlistSummary, 0, len(state))
	for _, name := range slices.Sorted(maps.Keys(state)) {
		lists = append(lists, WatchlistSummary{Name: name, Count: len(state[name])})
	}
	return lists, nil
}

func (s *Store) Watchlist(ctx context.Context, raw string) (Watchlist, error) {
	name, ok := watchName(raw)
	if !ok {
		return Watchlist{}, ErrWatchlist
	}
	state, err := s.watchState(ctx)
	if err != nil {
		return Watchlist{}, err
	}
	items, exists := state[name]
	if !exists {
		return Watchlist{}, ErrWatchlistAbsent
	}
	return Watchlist{Name: name, Assets: items}, nil
}

func (s *Store) ChangeWatchlist(ctx context.Context, raw string, action WatchAction, asset Indicator) (bool, error) {
	name, ok := watchName(raw)
	if !ok {
		return false, ErrWatchlist
	}
	switch action {
	case WatchCreate, WatchDelete:
		if asset != (Indicator{}) {
			return false, ErrWatchlist
		}
	case WatchAdd, WatchRemove:
		if !validWatchAsset(asset) {
			return false, ErrWatchlist
		}
	default:
		return false, ErrWatchlist
	}
	if s.db != nil {
		return s.changePostgresWatchlist(ctx, name, action, asset)
	}
	unlock, err := s.lockContext(ctx)
	if err != nil {
		return false, err
	}
	defer unlock()
	state, err := s.localWatchState()
	if err != nil {
		return false, err
	}
	changed, err := state.change(name, action, asset)
	if !changed || err != nil {
		return changed, err
	}
	data, err := json.Marshal(state)
	if err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := atomicWrite(filepath.Join(s.path, ".seguimiento.json"), data); err != nil {
		return false, err
	}
	return true, nil
}

func (state watchState) change(name string, action WatchAction, asset Indicator) (bool, error) {
	items, exists := state[name]
	switch action {
	case WatchCreate:
		if exists {
			return false, nil
		}
		if len(state) == maxWatchlists {
			return false, ErrWatchlistLimit
		}
		state[name] = []Indicator{}
	case WatchDelete:
		if !exists {
			return false, nil
		}
		delete(state, name)
	case WatchAdd, WatchRemove:
		if !exists {
			return false, ErrWatchlistAbsent
		}
		index, found := slices.BinarySearchFunc(items, asset, compareWatchAssets)
		if action == WatchRemove {
			if !found {
				return false, nil
			}
			state[name] = slices.Delete(items, index, index+1)
		} else {
			if found {
				return false, nil
			}
			if len(items) == maxWatchAssets {
				return false, ErrWatchlistLimit
			}
			state[name] = slices.Insert(items, index, asset)
		}
	}
	return true, nil
}

func (s *Store) watchState(ctx context.Context) (watchState, error) {
	if s.db != nil {
		return s.postgresWatchState(ctx)
	}
	unlock, err := s.lockContext(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	return s.localWatchState()
}

func (s *Store) localWatchState() (watchState, error) {
	file, err := os.Open(filepath.Join(s.path, ".seguimiento.json"))
	if errors.Is(err, os.ErrNotExist) {
		return make(watchState), nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxWatchStateSize+1))
	if err != nil {
		return nil, err
	}
	return decodeWatchState(data)
}

func decodeWatchState(data []byte) (watchState, error) {
	var state watchState
	if len(data) > maxWatchStateSize || json.Unmarshal(data, &state) != nil || state == nil || len(state) > maxWatchlists {
		return nil, errWatchState
	}
	for name, items := range state {
		canonical, valid := watchName(name)
		if !valid || canonical != name || items == nil || len(items) > maxWatchAssets {
			return nil, errWatchState
		}
		for index, item := range items {
			if !validWatchAsset(item) || (index > 0 && compareWatchAssets(items[index-1], item) >= 0) {
				return nil, errWatchState
			}
		}
	}
	return state, nil
}

func watchName(value string) (string, bool) {
	name := strings.TrimSpace(value)
	valid := len(name) > 0 && len(name) <= 80 && name != "." && name != ".." &&
		!strings.ContainsAny(name, "/\\") && utf8.ValidString(name) && strings.IndexFunc(name, unicode.IsControl) == -1
	return name, valid
}

func validWatchAsset(asset Indicator) bool {
	switch asset.Type {
	case "dominio", "ipv4", "ipv6", "red", "md5", "sha1", "sha256":
		return len(asset.Value) > 0 && len(asset.Value) <= 254 && utf8.ValidString(asset.Value) &&
			strings.IndexFunc(asset.Value, unicode.IsControl) == -1
	default:
		return false
	}
}

func compareWatchAssets(a, b Indicator) int {
	if order := strings.Compare(a.Type, b.Type); order != 0 {
		return order
	}
	return strings.Compare(a.Value, b.Value)
}
