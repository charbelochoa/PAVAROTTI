package main

import (
	"errors"
	"net/http"
	"strconv"

	"pavarotti/internal/analisis"
	"pavarotti/internal/caso"
)

func assetRoutes(mux *http.ServeMux, store *caso.Store) {
	parseQuery := func(w http.ResponseWriter, r *http.Request) (analisis.AssetQuery, bool) {
		params := r.URL.Query()
		query := analisis.AssetQuery{
			AssetKey: analisis.AssetKey{Type: params.Get("tipo"), Value: params.Get("valor")},
			Search:   params.Get("buscar"), After: params.Get("despues"),
		}
		if raw := params.Get("limite"); raw != "" {
			limit, err := strconv.Atoi(raw)
			if err != nil || limit < 1 || limit > 100 {
				assetError(w, analisis.ErrAssetQuery)
				return query, false
			}
			query.Limit = limit
		}
		return query, true
	}
	mux.HandleFunc("GET /api/activos", func(w http.ResponseWriter, r *http.Request) {
		query, ok := parseQuery(w, r)
		if !ok {
			return
		}
		page, err := analisis.ListAssets(r.Context(), store, query)
		if err != nil {
			assetError(w, err)
			return
		}
		respond(w, page)
	})
	mux.HandleFunc("GET /api/activos/ficha", func(w http.ResponseWriter, r *http.Request) {
		query, ok := parseQuery(w, r)
		if !ok {
			return
		}
		detail, err := analisis.DescribeAsset(r.Context(), store, query)
		if err != nil {
			assetError(w, err)
			return
		}
		respond(w, detail)
	})
}

func assetError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, analisis.ErrAssetQuery):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, caso.ErrNotFound):
		http.Error(w, "Activo inexistente en el expediente", http.StatusNotFound)
	case errors.Is(err, analisis.ErrLimit):
		http.Error(w, "El inventario admite hasta 10000 registros por expediente", http.StatusUnprocessableEntity)
	default:
		http.Error(w, "No se pudo consultar el inventario", http.StatusInternalServerError)
	}
}
