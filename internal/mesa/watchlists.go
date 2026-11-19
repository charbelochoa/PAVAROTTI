package mesa

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"pavarotti/internal/analisis"
	"pavarotti/internal/caso"
)

func watchlistRoutes(mux *http.ServeMux, store *caso.Store) {
	const path = "/api/seguimiento"
	const named = path + "/{lista}"
	mux.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
		lists, err := store.Watchlists(r.Context())
		if err != nil {
			watchlistError(w, err)
			return
		}
		respond(w, lists)
	})
	mux.HandleFunc("GET "+named, func(w http.ResponseWriter, r *http.Request) {
		review, err := analisis.ReviewWatchlist(r.Context(), store, r.PathValue("lista"))
		if err != nil {
			watchlistError(w, err)
			return
		}
		respond(w, review)
	})
	change := func(action caso.WatchAction, withAsset bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			var key analisis.AssetKey
			if withAsset {
				body := http.MaxBytesReader(w, r.Body, 4096)
				decoder := json.NewDecoder(body)
				decoder.DisallowUnknownFields()
				if err := decoder.Decode(&key); err != nil {
					watchlistError(w, caso.ErrWatchlist)
					return
				}
				var extra json.RawMessage
				if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
					watchlistError(w, caso.ErrWatchlist)
					return
				}
			}
			changed, err := analisis.ChangeWatchlist(r.Context(), store, r.PathValue("lista"), action, key)
			if err != nil {
				watchlistError(w, err)
				return
			}
			respond(w, map[string]bool{"changed": changed})
		}
	}
	mux.HandleFunc("PUT "+named, change(caso.WatchCreate, false))
	mux.HandleFunc("DELETE "+named, change(caso.WatchDelete, false))
	mux.HandleFunc("PUT "+named+"/activo", change(caso.WatchAdd, true))
	mux.HandleFunc("DELETE "+named+"/activo", change(caso.WatchRemove, true))
}

func watchlistError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, caso.ErrWatchlist), errors.Is(err, analisis.ErrAssetQuery):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, caso.ErrWatchlistAbsent):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, caso.ErrWatchlistLimit):
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
	default:
		http.Error(w, "No se pudo consultar o guardar el seguimiento", http.StatusInternalServerError)
	}
}
