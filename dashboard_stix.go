package main

import (
	"errors"
	"net/http"
	"strconv"

	"pavarotti/internal/analisis"
	"pavarotti/internal/caso"
)

func stixRoutes(mux *http.ServeMux, store *caso.Store) {
	mux.HandleFunc("GET /api/exportar/stix", func(w http.ResponseWriter, r *http.Request) {
		data, stats, err := analisis.ExportSTIX(r.Context(), store, nil)
		switch {
		case errors.Is(err, analisis.ErrSTIXEmpty), errors.Is(err, analisis.ErrSTIXLimit):
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		case err != nil:
			http.Error(w, "No se pudo exportar el expediente", http.StatusInternalServerError)
		default:
			w.Header().Set("Content-Type", "application/stix+json")
			w.Header().Set("Content-Disposition", `attachment; filename="PAVAROTTI-STIX.json"`)
			w.Header().Set("X-Pavarotti-Objects", strconv.Itoa(stats.Objects))
			w.Header().Set("X-Pavarotti-Exported", strconv.Itoa(stats.Exported))
			w.Header().Set("X-Pavarotti-Excluded", strconv.Itoa(stats.Excluded))
			_, _ = w.Write(data)
		}
	})
	mux.HandleFunc("GET /api/registro/{id}/stix", func(w http.ResponseWriter, r *http.Request) {
		offset := 0
		if after := r.URL.Query().Get("despues"); after != "" {
			value, err := strconv.Atoi(after)
			if err != nil || value < 0 {
				http.Error(w, analisis.ErrSTIXPage.Error(), http.StatusBadRequest)
				return
			}
			offset = value
		}
		links, err := analisis.RelatedSTIX(r.Context(), store, r.PathValue("id"), offset)
		switch {
		case errors.Is(err, caso.ErrNotFound):
			http.Error(w, "Objeto STIX inexistente", http.StatusNotFound)
		case errors.Is(err, analisis.ErrSTIXPage):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case errors.Is(err, analisis.ErrLimit):
			http.Error(w, "Las relaciones STIX admiten hasta 10000 registros por expediente", http.StatusUnprocessableEntity)
		case err != nil:
			http.Error(w, "No se pudieron consultar las relaciones STIX", http.StatusInternalServerError)
		default:
			respond(w, links)
		}
	})
}
