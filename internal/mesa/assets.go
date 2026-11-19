package mesa

import (
	"errors"
	"net/http"
	"net/url"
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
	mux.HandleFunc("GET /api/activos/red", func(w http.ResponseWriter, r *http.Request) {
		query, ok := parseQuery(w, r)
		if !ok {
			return
		}
		if query.Search != "" || query.Type != "" {
			assetError(w, analisis.ErrAssetQuery)
			return
		}
		page, err := analisis.ListNetworkObservations(r.Context(), store, query.Value, query.After, query.Limit)
		if err != nil {
			assetError(w, err)
			return
		}
		respond(w, page)
	})
	mux.HandleFunc("GET /api/activos/cobertura", func(w http.ResponseWriter, r *http.Request) {
		params, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			assetError(w, analisis.ErrAssetQuery)
			return
		}
		criteria := analisis.AssetCoverageCriteria{
			AssetKey: analisis.AssetKey{Type: params.Get("tipo"), Value: params.Get("valor")},
			From:     params.Get("desde"), To: params.Get("hasta"),
		}
		report, err := analisis.CoverAsset(r.Context(), store, criteria)
		if err != nil {
			assetError(w, err)
			return
		}
		respond(w, report)
	})
	mux.HandleFunc("GET /api/activos/relaciones", func(w http.ResponseWriter, r *http.Request) {
		params, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			assetError(w, analisis.ErrAssetQuery)
			return
		}
		criteria := analisis.AssetRelationCriteria{
			AssetKey: analisis.AssetKey{Type: params.Get("tipo"), Value: params.Get("valor")},
			From:     params.Get("desde"), To: params.Get("hasta"),
		}
		report, err := analisis.RelateAsset(r.Context(), store, criteria)
		if err != nil {
			assetError(w, err)
			return
		}
		respond(w, report)
	})
}

func assetError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, analisis.ErrAssetQuery):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, caso.ErrNotFound):
		http.Error(w, "Activo inexistente en el expediente", http.StatusNotFound)
	case errors.Is(err, analisis.ErrLimit):
		http.Error(w, "La consulta de activos supera el límite de 10000 registros", http.StatusUnprocessableEntity)
	case errors.Is(err, analisis.ErrSnapshotBytes), errors.Is(err, analisis.ErrAssetRelationLimit):
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
	default:
		http.Error(w, "No se pudo consultar el inventario", http.StatusInternalServerError)
	}
}
