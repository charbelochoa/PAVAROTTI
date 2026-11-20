package mesa

import (
	"errors"
	"net/http"
	"net/url"

	"pavarotti/internal/analisis"
	"pavarotti/internal/caso"
)

func httpComparisonRoute(mux *http.ServeMux, store *caso.Store) {
	mux.HandleFunc("GET /api/http/comparar", func(w http.ResponseWriter, r *http.Request) {
		params, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			http.Error(w, "Consulta de comparación inválida", http.StatusBadRequest)
			return
		}
		window := func(side string) analisis.HTTPWindow {
			return analisis.HTTPWindow{Origin: params.Get("origen_" + side), Capture: params.Get("captura_" + side),
				From: params.Get("desde_" + side), To: params.Get("hasta_" + side)}
		}
		report, err := analisis.CompareHTTP(r.Context(), store, analisis.HTTPCompareCriteria{Baseline: window("a"), Current: window("b")})
		if r.Context().Err() != nil {
			return
		}
		switch {
		case errors.Is(err, analisis.ErrHTTPComparisonCriteria):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case errors.Is(err, analisis.ErrHTTPComparisonLimit), errors.Is(err, analisis.ErrSnapshotBytes):
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		case err != nil:
			http.Error(w, "No se pudo comparar el historial HTTP", http.StatusInternalServerError)
		default:
			respond(w, report)
		}
	})
}
